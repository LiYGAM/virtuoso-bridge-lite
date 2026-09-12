"""Focused safety checks for queue deadlines, transport and machine results."""
import copy
import io
import json
import threading
import time
from types import SimpleNamespace

import pytest

from virtuoso_bridge import cli, CompletionStatus, OperationClass, VirtuosoClient
from virtuoso_bridge.transport import tunnel
from virtuoso_bridge.transport.tunnel import SSHClient
from .test_bridge_daemon_timeout_drain import _load_functions
from .test_bridge_timeout import _v3_frame

pytestmark = pytest.mark.unit


@pytest.mark.parametrize('variant', ['3', '27'])
@pytest.mark.parametrize('times,expired', [([60.0], True), ([4.0, 5.0], True), ([3.0, 4.0], False)])
def test_queue_deadline_never_dispatches_expired_work(variant, times, expired):
    clock = iter(times)
    sent, timers, closed = [], [], []
    entry = {'state': 'queued', 'request_generation': 'g'}
    output = io.BytesIO() if variant == '3' else io.StringIO()
    stdin = io.BytesIO() if variant == '3' else io.StringIO()

    class Timer:
        def __init__(self, seconds, *args, **kwargs):
            timers.append(seconds)
        def start(self): pass
        def cancel(self): pass

    def finalize(request_id, generation, state, **fields):
        entry.update(state=state, **fields)
        return True

    ns = {
        '_monotonic': lambda: next(clock), 'time': time,
        '_mark_request_running': lambda *a: True, '_finalize_request': finalize,
        '_safe_sendall': lambda c, data: sent.append(data),
        '_safe_close_connection': lambda c: closed.append(True),
        '_format_client_response': lambda *a, **kw: b'response',
        'DAEMON_EPOCH': 'epoch', 'DAEMON_BUILD_SHA256': 'b' * 64,
        'threading': SimpleNamespace(Event=threading.Event, Timer=Timer),
        'sys': SimpleNamespace(stdin=SimpleNamespace(buffer=stdin) if variant == '3' else stdin,
                               stdout=SimpleNamespace(buffer=output) if variant == '3' else output),
        'json': json, '_RESPONSE_DRAIN_WARNING_SECONDS': 10,
        'watchdog_callback': lambda *a: None,
        'read_until_delimiter': lambda *a, **kw: (_ for _ in ()).throw(StopIteration()),
    }
    # Stop after the first response read to observe the dispatch budget.
    class StopAfterDispatch(BaseException): pass
    ns['read_until_delimiter'] = lambda *a, **kw: (_ for _ in ()).throw(StopAfterDispatch())
    _load_functions('ramic_bridge_daemon_' + variant + '.py',
                    {'handle_external_connection', '_expire_queued_request',
                     'RequestProtocolError', 'ResponseStreamClosed', 'ResponseDrainTimeout'}, ns)
    class LegacyString(str):
        def encode(self, *args): return self
    code = LegacyString('reviewMutation()') if variant == '27' else 'reviewMutation()'
    admitted = (object(), None, code, 5.0, 'r', 'mutating', 3, 'a' * 64, 'g', False, 5.0)
    try:
        ns['handle_external_connection'](admitted)
    except StopAfterDispatch:
        assert not expired
    assert closed == [True]
    if expired:
        assert not output.getvalue() and not timers
        assert entry['state'] == 'expired_before_dispatch'
        assert entry['pre_dispatch_proof']['execution_dispatched'] is False
        assert entry['pre_dispatch_proof']['request_generation'] == 'g'
        assert len(sent) == 1
    else:
        assert output.getvalue() and timers == [1.0]
        assert entry['state'] == 'queued'  # The spy did not fabricate terminal proof.


@pytest.mark.parametrize('protocol', [2, 3])
def test_expiry_response_is_not_dispatched(protocol):
    raw = b'\x15REQUEST_EXPIRED_BEFORE_DISPATCH'
    if protocol == 3:
        raw = _v3_frame('r', raw[1:], status='expired_before_dispatch', marker='NAK',
                        request_digest_sha256='a' * 64)
    result = VirtuosoClient._parse_response(raw, 1.0, operation_class=OperationClass.MUTATING,
                                           request_id='r', request_digest_sha256='a' * 64)
    assert result.completion == CompletionStatus.NOT_DISPATCHED


def test_pre_dispatch_proof_requires_exact_identity_and_no_execution():
    expected = dict(request_digest_sha256='a' * 64, operation_class='mutating',
                    daemon_epoch='epoch', daemon_build_sha256='b' * 64,
                    request_generation='g', protocol_version=3)
    proof = dict(expected, request_id='r', state='expired_before_dispatch', schema_version=1,
                 execution_dispatched=False, finished_at_epoch=123.0)
    request = dict(proof, admitted_daemon_epoch='epoch', admitted_daemon_build_sha256='b' * 64,
                   pre_dispatch_proof=proof)
    assert cli._terminal_proof_errors(request, 'r', expected) == []
    for key in ['request_id', 'request_generation', 'admitted_daemon_epoch', 'execution_dispatched']:
        changed = dict(request, **{key: 'conflict'})
        assert cli._terminal_proof_errors(changed, 'r', expected)
    for key in ['daemon_build_sha256', 'protocol_version', 'execution_dispatched', 'finished_at_epoch']:
        changed = dict(request, pre_dispatch_proof=dict(proof, **{key: 'conflict'}))
        assert cli._terminal_proof_errors(changed, 'r', expected)


@pytest.mark.parametrize('changed', [False, True])
def test_connect_preserves_deployment_and_refuses_concurrent_state_change(monkeypatch, changed):
    client = SSHClient(remote_host='host', profile='review', auth_token='fixture')
    state = {'port': 10, 'deployment_id': 'unchanged', 'profile_config': {'remote_host': 'host'}}
    snapshots = iter([copy.deepcopy(state), dict(state, deployment_id='changed') if changed else copy.deepcopy(state)])
    monkeypatch.setattr(client, 'read_state', lambda *a: next(snapshots))
    monkeypatch.setattr(client, 'staged_profile_config_matches_current', lambda *a: True)
    monkeypatch.setattr(client, '_require_runner', lambda: SimpleNamespace(tunnel_pid=99))
    def connect_only(**kwargs): client._local_port = 11
    monkeypatch.setattr(client, 'ensure_tunnel', connect_only)
    def forbidden(*a, **kw): pytest.fail('Transport connect tried to stage resources')
    monkeypatch.setattr(client, 'ensure_remote_setup', forbidden)
    monkeypatch.setattr(client, 'warm', forbidden)
    saved = []
    monkeypatch.setattr(tunnel, '_atomic_write_json', lambda path, data: saved.append(copy.deepcopy(data)))
    if changed:
        with pytest.raises(RuntimeError, match='state changed'): client.connect()
        assert not saved
    else:
        assert client.connect()['deployment_changed'] is False
        assert saved[0]['deployment_id'] == 'unchanged'
        assert saved[0]['port'] == 11 and saved[0]['tunnel_pid'] == 99


@pytest.mark.parametrize('fault', [None, 'busy', 'epoch', 'identity', 'stale', 'pid', 'queue_type'])
def test_session_status_is_pinned_idle_and_read_only(monkeypatch, capsys, fault):
    ledger = dict(requests=[], queue_depth=0, active_request_id=None,
                  daemon_epoch='new', daemon_build_sha256='b' * 64, daemon_pid=123,
                  heartbeat_at_epoch=time.time())
    deployment = dict(running_daemon_epoch='new', running_identity_verified=True,
                      running_heartbeat_fresh=True, running_daemon_sha256='b' * 64)
    if fault == 'busy': ledger['active_request_id'] = 'other'
    if fault == 'epoch': ledger['daemon_epoch'] = 'other'
    if fault == 'identity': deployment['running_identity_verified'] = False
    if fault == 'stale': ledger['heartbeat_at_epoch'] = 0
    if fault == 'pid': ledger['daemon_pid'] = None
    if fault == 'queue_type': ledger['queue_depth'] = 0.5
    monkeypatch.setattr(cli, '_load_cli_env', lambda: None)
    monkeypatch.setattr(SSHClient, 'read_request_status', lambda *a, **kw: ledger)
    monkeypatch.setattr(SSHClient, 'deployment_status', lambda *a, **kw: deployment)
    monkeypatch.setattr(SSHClient, 'from_env', lambda *a, **kw: pytest.fail('session-status opened CIW/staged files'))
    if fault:
        with pytest.raises(RuntimeError): cli.cli_session_status(expected_epoch='new')
    else:
        assert cli.cli_session_status(expected_epoch='new') == 0
        assert json.loads(capsys.readouterr().out)['idle'] is True


def test_machine_envelope_logs_are_stderr_and_pending_is_not_failure(monkeypatch, capsys):
    monkeypatch.setattr(cli, '_load_cli_env', lambda: print('using .env: fixture', file=cli.sys.stderr))
    monkeypatch.setattr(SSHClient, 'deployment_status', lambda *a, **kw: {
        'staged_update_pending': True, 'running_available': True, 'running_heartbeat_fresh': True})
    assert cli.main(['--json-envelope', 'deployment-status']) == 0
    captured = capsys.readouterr()
    envelope = json.loads(captured.out)
    assert envelope['status'] == 'pending' and envelope['errors'] == []
    assert envelope['data']['staged_update_pending'] is True
    assert 'using .env' in captured.err and 'using .env' not in captured.out


@pytest.mark.parametrize('payload,code,status', [([], 0, 'success'),
    ({'completion': 'timed_out_unknown', 'errors': ['timeout']}, 1, 'unknown')])
def test_machine_envelope_keeps_arrays_and_unknown(monkeypatch, capsys, payload, code, status):
    def handler():
        print(json.dumps(payload))
        return code
    monkeypatch.setattr(cli, 'cli_status', handler)
    assert cli.main(['--json-envelope', 'status']) == code
    envelope = json.loads(capsys.readouterr().out)
    assert envelope['data'] == payload and envelope['status'] == status


def test_machine_mode_rejects_lost_structured_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, 'cli_status', lambda: print('unexpected prose'))
    assert cli.main(['--json-envelope', 'status']) == 1
    output = capsys.readouterr()
    assert json.loads(output.out)['status'] == 'error'
    assert 'unexpected prose' in output.err


@pytest.mark.parametrize('variant', ['3', '27'])
def test_deadline_rejects_nonfinite_timeout(variant):
    ns = {'_MAX_EXECUTION_TIMEOUT_SECONDS': 60.0, '_string_types': (str,)}
    _load_functions('ramic_bridge_daemon_' + variant + '.py', {'_validate_request', 'RequestProtocolError'}, ns)
    for timeout in (float('nan'), float('inf'), -1, 0):
        with pytest.raises(ns['RequestProtocolError'], match='INVALID_TIMEOUT'):
            ns['_validate_request']({'skill': '1+1', 'timeout': timeout})


@pytest.mark.parametrize('variant', ['3', '27'])
def test_expiry_finalize_is_generation_scoped_and_terminal(variant):
    ns = {'_ACTIVE_STATES': ('running', 'timed_out_pending'), '_ACTIVE_REQUEST_ID': None,
          '_STATE_LOCK': threading.Lock(), 'time': time, '_write_request_state': lambda: None,
          '_REQUESTS': {'r': {'state': 'queued', 'request_generation': 'new'}}}
    _load_functions('ramic_bridge_daemon_' + variant + '.py', {'_finalize_request'}, ns)
    assert not ns['_finalize_request']('r', 'old', 'expired_before_dispatch')
    assert ns['_REQUESTS']['r']['state'] == 'queued'
    assert ns['_finalize_request']('r', 'new', 'expired_before_dispatch')
    assert not ns['_finalize_request']('r', 'new', 'succeeded')
    assert ns['_REQUESTS']['r']['state'] == 'expired_before_dispatch'
