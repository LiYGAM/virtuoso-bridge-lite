"""Regression checks for the final development-toolchain audit."""
from types import SimpleNamespace

import pytest

from virtuoso_bridge import VirtuosoClient
from virtuoso_bridge.models import VirtuosoResult

pytestmark = pytest.mark.unit


@pytest.mark.parametrize('kind', ['layout', 'schematic', 'symbol'])
@pytest.mark.parametrize('value', ['nil', 't'])
def test_edit_save_requires_confirmed_true(kind, value):
    client = VirtuosoClient(log_to_ciw=False)
    calls = []
    client.execute_skill = lambda code, **kw: (calls.append(code), VirtuosoResult(status='success', output=value))[1]
    editor = getattr(client, kind).modify('owned', 'fixture')
    if value == 'nil':
        with pytest.raises(RuntimeError, match='save was not confirmed'):
            with editor as batch: batch.add('t')
    else:
        with editor as batch: batch.add('t')
    assert len(calls) == 1 and 'unless(dbSave(rbCv)' in calls[0]
    assert 'save-target-mismatch' in calls[0]


def test_layout_close_happens_after_successful_save():
    client = VirtuosoClient(log_to_ciw=False)
    calls = []
    client.execute_skill = lambda code, **kw: (calls.append(code), VirtuosoResult(status='success', output='t'))[1]
    with client.layout.modify('owned', 'fixture') as batch: batch.close()
    assert calls[0].index('unless(dbSave') < calls[0].index('dbClose(')


@pytest.mark.parametrize('state,fault', [('running', 'healthy'), ('timed_out_pending', 'request-timeout-pending'),
                                       ('late_waiting_operator', 'request-needs-attention')])
def test_monitor_reports_pending_work_without_workspace_quarantine(tmp_path, state, fault):
    from virtuoso_bridge.recovery import RecoveryEngine, RecoveryStore
    snapshot = {'identity_verified': True, 'daemon_alive': True, 'heartbeat_fresh': True,
                'transport_available': True, 'idle': False,
                'blocking_requests': [{'request_id': 'owned', 'state': state}]}
    backend = SimpleNamespace(snapshot=lambda: dict(snapshot))
    engine = RecoveryEngine(RecoveryStore(tmp_path, 'fixture'), backend)
    assert engine.inspect()['fault_class'] == fault
    if state != 'running':
        result = engine.run(automatic=True, timeout=1)
        assert result['stop_reason'] == 'original-request-pending-no-replay'
        assert result['actions'] == [] and not result['original_request_replayed']
        assert not result['workflow_resume_allowed']


def test_loaded_version_uses_ciw_order_not_client_timestamps(tmp_path, monkeypatch):
    import hashlib
    from virtuoso_bridge.script_loading import prepare_script, finish_receipt, loaded_scripts, managed_load_command
    monkeypatch.setenv('VB_HOME', str(tmp_path / 'runtime'))
    source = tmp_path / 'owned.il'
    client = VirtuosoClient(log_to_ciw=False)
    prepared = []
    # B ran first despite its later client preparation timestamp; A ran last.
    for text, timestamp in [('"B"', 20), ('"A"', 10)]:
        source.write_text(text)
        item = prepare_script(client, source)
        item['started_at'] = timestamp
        finish_receipt(client, item, VirtuosoResult(status='success', metadata={'daemon_epoch': 'epoch'}))
        prepared.append(item)
    key = hashlib.sha256(str(source.resolve()).encode()).hexdigest()
    code = managed_load_command('load("owned")', prepared[-1])
    assert code.index(prepared[-1]['load_id']) < code.index('load("owned")')
    client.execute_skill = lambda *a, **kw: VirtuosoResult(status='success', metadata={'daemon_epoch': 'epoch'},
        output=f'("epoch" nil 1 (("{key}" "{prepared[-1]["load_id"]}")))')
    assert loaded_scripts(client)['latest'][0]['source_sha256'] == prepared[-1]['source_sha256']
    client.execute_skill = lambda *a, **kw: VirtuosoResult(status='success', metadata={'daemon_epoch': 'epoch'},
                                                          output='("epoch" nil 1 nil)')
    assert loaded_scripts(client)['latest'][0]['status'] == 'load-order-unverified'


def test_readonly_mode_reaches_window_and_bound_load(tmp_path, monkeypatch):
    monkeypatch.setenv('VB_HOME', str(tmp_path / 'runtime'))
    source = tmp_path / 'source.il'; source.write_text('t')
    client = VirtuosoClient(log_to_ciw=False)
    calls = []
    client.execute_skill = lambda code, **kw: (calls.append(code), VirtuosoResult(status='success', output='t'))[1]
    assert client.run_il_file(source, 'owned', 'fixture', mode='r').ok
    assert '?mode "r"' in calls[0] and 'window-mode-mismatch' in calls[0]
    assert 'equal(cv~>mode "r")' in calls[1]
    calls.clear()
    assert client.run_il_file(source, 'owned', 'fixture', mode='r', save=True).completion.value == 'not_dispatched'
    assert client.run_il_file(source, 'owned', 'fixture', mode='w').completion.value == 'not_dispatched'
    assert not calls
