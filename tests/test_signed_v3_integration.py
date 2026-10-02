"""Signed transport must preserve the fork's v3 admission and replay contracts."""
import hashlib
import json
import socket
import threading

import pytest

from virtuoso_bridge import VirtuosoClient
from virtuoso_bridge import daemon_auth
from virtuoso_bridge.models import CompletionStatus, OperationClass
from tests.test_daemon_auth import _import_py3_daemon


def signed_request(token, nonce="ab" * 16):
    value = dict(proto=1, nonce=nonce, skill="1+1", timeout=2.0,
                 protocol_version=3, request_id="signed-request", operation_class="mutating",
                 supported_protocol_versions=[3, 2], exclusive=True)
    value["mac"] = daemon_auth.request_mac(token, nonce=nonce, skill=value["skill"], timeout=2.0)
    value["frame_mac"] = daemon_auth.v3_request_mac(token, value)
    value["mac"] = value["frame_mac"]
    return value


class Connection:
    def __init__(self):
        self.output = b""
    def sendall(self, data):
        self.output += data
    def settimeout(self, timeout):
        pass
    def close(self):
        pass


@pytest.mark.parametrize("field,value", [("request_id", "other"), ("operation_class", "read_only"),
                                         ("exclusive", False), ("protocol_version", 2), ("strip_metadata", None)])
def test_signed_metadata_tampering_never_enters_queue(monkeypatch, tmp_path, field, value):
    module = _import_py3_daemon(monkeypatch, tmp_path)
    request = signed_request(module.BRIDGE_TOKEN)
    if field == "strip_metadata":
        for key in ("protocol_version", "frame_mac", "request_id", "operation_class", "exclusive", "supported_protocol_versions"):
            request.pop(key, None)
    else:
        request[field] = value
    monkeypatch.setattr(module, "_receive_request", lambda conn: json.dumps(request).encode())
    connection = Connection()
    assert not module._admit_external_connection(connection, ("127.0.0.1", 1))
    assert b"AuthError" in connection.output
    assert module._REQUEST_QUEUE.empty()
    assert not module._REQUESTS


@pytest.mark.parametrize("tamper_response", [False, True])
def test_signed_client_roundtrip_reuses_cached_frame_without_readmission(monkeypatch, tmp_path, tamper_response):
    module = _import_py3_daemon(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "_write_request_state", lambda: None)
    admitted = []
    errors = []
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        server.settimeout(5)
        port = server.getsockname()[1]
        def serve():
            try:
                # One hello plus two executions sharing the same logical ID.
                for _ in range(4 if tamper_response else 3):
                    conn, addr = server.accept()
                    with conn:
                        if module._admit_external_connection(conn, addr):
                            item = module._REQUEST_QUEUE.get_nowait()
                            signed_conn, _, skill, _, request_id = item[:5]
                            admitted.append(skill)
                            digest = hashlib.sha256(("mutating\0" + skill).encode()).hexdigest()
                            response = module._format_client_response(
                                3, request_id, "succeeded", "STX", "2", request_digest_sha256=digest)
                            module._REQUESTS[request_id]["state"] = "succeeded"
                            module._RESPONSE_CACHE[request_id] = response
                            if tamper_response:
                                signature = module._mac_hex(module._RESP_DOMAIN, signed_conn.nonce, b"\x02", response).encode("ascii")
                                conn.sendall(b"\x02" + signature + response[:-1] + bytes([response[-1] ^ 1]))
                            else:
                                signed_conn.sendall(response)
            except BaseException as exc:
                errors.append(exc)
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        client = VirtuosoClient(port=port, daemon_token=module.BRIDGE_TOKEN)
        first = client.execute_skill("1+1", timeout=3, request_id="same-request", operation_class=OperationClass.MUTATING)
        second = client.execute_skill("1+1", timeout=3, request_id="same-request", operation_class=OperationClass.MUTATING)
        worker.join(6)
        assert not worker.is_alive()
        assert not errors
    assert second.completion == CompletionStatus.CONFIRMED, second
    assert second.output == "2" and second.protocol_version == 3
    if tamper_response:
        assert first.completion == CompletionStatus.TIMED_OUT_UNKNOWN, first
    else:
        assert first.completion == CompletionStatus.CONFIRMED and first.output == "2"
        assert first.protocol_version == 3
    assert admitted == ["1+1"]
    assert module._REQUESTS["same-request"]["duplicate_count"] == 1

def test_status_token_lookup_is_read_only_and_closes_transport(monkeypatch):
    from types import SimpleNamespace
    from virtuoso_bridge import cli
    from virtuoso_bridge.transport.tunnel import SSHClient
    commands, closed = [], []
    def read(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=1, stdout="")
    fake = SimpleNamespace(ssh_runner=SimpleNamespace(run_command=read), close=lambda: closed.append(True))
    monkeypatch.setattr(SSHClient, "from_env", lambda **kwargs: fake)
    assert cli._state_or_local_daemon_token({"remote_host": "fixture"}, None) is None
    assert commands == ["cat ~/.virtuoso-bridge/bridge_token 2>/dev/null"]
    assert closed == [True]
