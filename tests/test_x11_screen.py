from pathlib import Path
from types import SimpleNamespace
import pytest
from virtuoso_bridge.virtuoso import x11


class Runner:
    def __init__(self, payload=b"\x89PNG\r\n\x1a\nfixture", fail=False):
        self.payload, self.fail, self.code = payload, fail, ""

    def upload(self, local, remote):
        self.code = Path(local).read_text()
        return SimpleNamespace(returncode=0)

    def download(self, remote, local, timeout=None):
        if self.fail:
            return SimpleNamespace(returncode=1, stderr="download failed")
        Path(local).write_bytes(self.payload)
        return SimpleNamespace(returncode=0)


def prepare(monkeypatch):
    monkeypatch.setattr(x11, "_ensure_helper", lambda *a: "/helper.py")
    monkeypatch.setattr(x11, "_detect_remote_python", lambda *a: "python3")
    monkeypatch.setattr(x11, "_run", lambda *a, **kw: SimpleNamespace(returncode=0))


def test_capture_window_and_desktop_without_skill(monkeypatch, tmp_path):
    prepare(monkeypatch)
    monkeypatch.setattr(x11, "list_windows", lambda *a: [
        {"window_id": "0x1", "frame_id": "0x2", "mapped": True}])
    runner = Runner()
    result = x11.capture_screen(runner, "u", tmp_path / "form.png", window_id="0x1")
    assert result["skill_executed"] is False
    assert "window_foreign_new(2)" in runner.code
    assert "LD_LIBRARY_PATH" in runner.code
    x11.capture_screen(runner, "u", tmp_path / "desktop.png")
    assert "gnome-screenshot" in runner.code


@pytest.mark.parametrize("payload,fail", [(b"not png", False), (b"", True)])
def test_failed_capture_never_publishes_output(monkeypatch, tmp_path, payload, fail):
    prepare(monkeypatch)
    with pytest.raises(RuntimeError):
        x11.capture_screen(Runner(payload, fail), "u", tmp_path / "bad.png")
    assert not (tmp_path / "bad.png").exists()


def test_missing_window_and_existing_output(monkeypatch, tmp_path):
    prepare(monkeypatch)
    monkeypatch.setattr(x11, "list_windows", lambda *a: [])
    with pytest.raises(ValueError):
        x11.capture_screen(Runner(), "u", tmp_path / "new.png", window_id="0x1")
    existing = tmp_path / "existing.png"
    existing.write_bytes(b"keep")
    with pytest.raises(ValueError):
        x11.capture_screen(Runner(), "u", existing)
    assert existing.read_bytes() == b"keep"
