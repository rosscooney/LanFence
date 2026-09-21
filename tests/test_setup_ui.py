# Copyright (c) 2026-present Stable State Consulting Ltd
# SPDX-License-Identifier: MIT

from copy import deepcopy
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from rich.console import Console
from typer.testing import CliRunner

from lanfence.cli import app
from lanfence.channels import load_channels_config_file, ConfigFileError
from lanfence.config import Config
from lanfence.db import DeviceStore
from lanfence.setup_ui import (
    patch_value, validation_errors, parse_field, diff_lines, render_overview,
    warnings_for, observed_servers,
)

runner = CliRunner()


def run_setup(path, answers):
    with patch('lanfence.cli._stdin_is_interactive', return_value=True), patch(
        'lanfence.cli.send_channel_test_message', return_value=(True, 'accepted')
    ) as transport:
        result = runner.invoke(app, ['setup', '--config', str(path)], input=answers)
    assert result.exit_code == 0, (result.output, result.exception)
    return result, transport


def test_open_and_noop_save_never_create_file(tmp_path):
    path = tmp_path / 'missing' / 'config.yaml'
    result, transport = run_setup(path, 'save\nexit\n')
    assert 'No changes' in result.output
    assert 'LAN Fence setup' in result.output
    assert not path.parent.exists()
    transport.assert_not_called()


def test_boolean_field_prompt_shows_yn_hint_for_current_value(tmp_path):
    path = tmp_path / 'config.yaml'
    result, _ = run_setup(path, '4\n1\nback\nback\nexit\n')
    assert 'enabled [y/N]' in result.output


def test_shared_draft_channel_and_scanning(tmp_path):
    path = tmp_path / 'config.yaml'
    result, transport = run_setup(path,
        '2\n3\n2m\nback\n1\nslack\nhttps://hooks.slack.com/SECRET\n\ny\nn\n'
        'review\nsave\nn\nexit\n')
    raw = yaml.safe_load(path.read_text())
    assert raw['scan'] == {'scan_interval_seconds': 120}
    assert raw['alerts']['slack']['enabled'] is True
    assert raw['alerts']['slack']['webhook_url'].endswith('/SECRET')
    assert 'SECRET' not in result.output
    assert 'digest' not in raw
    assert path.stat().st_mode & 0o777 == 0o600
    transport.assert_not_called()


@pytest.mark.parametrize('ending', ['discard\nexit\n', 'exit\ndiscard\n', ''])
def test_unsaved_edits_leave_original_untouched(tmp_path, ending):
    path = tmp_path / 'config.yaml'
    original = '# keep this comment\nscan:\n  interface: eth0\n'
    path.write_text(original)
    run_setup(path, '2\n1\neth1\nback\n' + ending)
    assert path.read_text() == original


def test_save_then_cancel_preserves_completed_save(tmp_path):
    path = tmp_path / 'config.yaml'
    run_setup(path, '2\n1\neth1\nback\nsave\ny\n2\n1\neth2\n')
    assert yaml.safe_load(path.read_text())['scan']['interface'] == 'eth1'


def test_reset_and_null_have_distinct_persistence(tmp_path):
    path = tmp_path / 'config.yaml'
    path.write_text('scan:\n  interface: eth0\n  subnet: 192.168.1.0/24\n')
    run_setup(path, '2\n1\nreset\n2\nnull\nback\nsave\ny\nexit\n')
    assert yaml.safe_load(path.read_text()) == {'scan': {'subnet': None}}


@pytest.mark.parametrize(('path', 'text', 'expected'), [
    ('scan.passive', 'no', False), ('scan.offline_grace_seconds', '5m', 300),
    ('scan.offline_after_missed_scans', '4', 4), ('alerts.min_severity', 'high', 'high'),
    ('vendor_file', 'null', None), ('db_path', '~/new.db', '~/new.db'),
    ('digest.channels', 'email, slack', ['email', 'slack']),
])
def test_field_types(path, text, expected):
    assert parse_field(path, text) == expected


def test_invalid_values_and_secret_safe_errors():
    assert validation_errors({'scan': {'scan_interval_seconds': float('inf')}})
    assert validation_errors({'scan': {'subnet': 'bad'}})
    assert validation_errors({'alerts': {'slack': {'enabled': True}}}, complete=True)
    errors = validation_errors({'alerts': {'slack': {'timeout_seconds': 'PASSWORD'}}})
    assert 'PASSWORD' not in str(errors)
    assert 'alerts.slack.timeout_seconds' in str(errors)


def test_patch_preserves_unrelated_extension_values():
    raw = {'scan': {'interface': 'eth0'}, 'extension': {'secret': 'keep'}}
    updated = patch_value(raw, 'scan.interface')
    assert updated == {'extension': {'secret': 'keep'}}
    assert raw['scan']['interface'] == 'eth0'


def test_schema_unknown_keys_are_refused_without_discarding_data(tmp_path):
    path = tmp_path / 'config.yaml'
    original = 'extension: TOP_SECRET\n'
    path.write_text(original)
    with pytest.raises(ConfigFileError) as exc:
        load_channels_config_file(path)
    assert 'TOP_SECRET' not in str(exc.value)
    assert path.read_text() == original


def test_dhcp_add_edit_duplicate_remove(tmp_path):
    path = tmp_path / 'config.yaml'
    result, _ = run_setup(path,
        '4\na\nadd\nRouter\neth0\n192.168.1.1\ny\n'
        'add\nDuplicate\neth0\n192.168.1.1\n'
        'edit\n1\nBackup\neth0.20\n192.168.20.1\ny\n'
        'add\nOther\neth1\n192.168.2.1\ny\nremove\n2\ny\n'
        'back\nback\nsave\ny\nexit\n')
    assert 'Invalid approval' in result.output
    assert yaml.safe_load(path.read_text())['dhcp_servers']['approved'] == [
        {'name': 'Backup', 'interface': 'eth0.20', 'server_ip': '192.168.20.1'}]


def test_observed_server_read_does_not_create_database(tmp_path):
    path = tmp_path / 'missing.db'
    import sqlite3
    with pytest.raises(sqlite3.OperationalError):
        observed_servers(Config(db_path=path))
    assert not path.exists()


def test_observed_server_approval_requires_confirmation(tmp_path):
    from datetime import datetime, timezone
    db = tmp_path / 'db.sqlite'
    with DeviceStore(db) as store:
        store.record_dhcp_server_observation(
            interface='eth0', server_id='192.168.1.1', message_type='offer',
            observed_at=datetime.now(timezone.utc), source_ip='192.168.1.1',
            source_mac=None, relay_ip=None, router=None, dns=None)
    path = tmp_path / 'config.yaml'
    path.write_text(yaml.safe_dump({'db_path': str(db)}))
    before = path.read_bytes()
    run_setup(path, '4\na\nobserved\n1\nRouter\n\n\nn\nback\nback\nexit\n')
    assert path.read_bytes() == before
    run_setup(path, '4\na\nobserved\n1\nRouter\n\n\ny\nback\nback\nsave\ny\nexit\n')
    assert yaml.safe_load(path.read_text())['dhcp_servers']['approved'][0]['server_ip'] == '192.168.1.1'


def test_warnings_and_narrow_layout(tmp_path):
    raw = {'scan': {'passive': False}, 'dhcp_servers': {'enabled': True},
           'discovery': {'mdns': True}, 'digest': {'channels': ['slack']}}
    warnings = warnings_for(Config.model_validate(raw))
    assert len(warnings) == 4
    stream = StringIO()
    render_overview(Console(file=stream, width=36, color_system=None), raw)
    assert 'LAN Fence setup' in stream.getvalue()
    assert 'Warning:' in stream.getvalue()


def test_render_overview_never_prints_file_path_or_status():
    stream = StringIO()
    render_overview(Console(file=stream, width=80, color_system=None), {})
    output = stream.getvalue()
    assert 'File:' not in output
    assert 'Unsaved changes' not in output
    assert 'Status:' not in output


def test_diff_hides_channel_values_and_unknown_values():
    before = {'alerts': {'slack': {'webhook_url': 'SECRET1'}}}
    after = deepcopy(before)
    after['alerts']['slack']['webhook_url'] = 'SECRET2'
    after['extension'] = 'SECRET3'
    lines = '\n'.join(diff_lines(before, after))
    assert 'SECRET' not in lines
    assert '[replaced]' in lines


def test_diff_hides_web_password_hash_and_salt():
    before = {}
    after = {'web': {'password_hash': 'HASHVALUE', 'password_salt': 'SALTVALUE'}}
    lines = '\n'.join(diff_lines(before, after))
    assert 'HASHVALUE' not in lines
    assert 'SALTVALUE' not in lines
    assert 'web.password (set)' in lines


def test_diff_web_password_change_and_clear_wording():
    before = {'web': {'password_hash': 'OLD', 'password_salt': 'OLDSALT'}}
    changed = {'web': {'password_hash': 'NEW', 'password_salt': 'NEWSALT'}}
    assert 'web.password (changed)' in '\n'.join(diff_lines(before, changed))
    assert 'web.password (cleared)' in '\n'.join(diff_lines(before, {}))


def test_warnings_for_flags_web_enabled_without_password():
    cfg = Config(web={'enabled': True})
    assert any('cannot start until' in w for w in warnings_for(cfg))


def test_warnings_for_silent_when_web_disabled_or_password_set():
    assert warnings_for(Config()) == []
    cfg = Config(web={'enabled': True, 'password_hash': 'a', 'password_salt': 'b'})
    assert warnings_for(cfg) == []


def test_concurrent_edit_not_overwritten(tmp_path):
    path = tmp_path / 'config.yaml'
    path.write_text('{}\n')
    from lanfence.channels import save_channels_config_file
    def concurrent_save(loaded, draft):
        path.write_text('scan: {interface: external}\n')
        return save_channels_config_file(loaded, draft)
    with patch('lanfence.cli._stdin_is_interactive', return_value=True), patch(
        'lanfence.cli.save_channels_config_file', side_effect=concurrent_save
    ):
        result = runner.invoke(app, ['setup', '--config', str(path)],
                               input='2\n1\neth1\nback\nsave\ny\n')
    assert result.exit_code == 2
    assert 'changed on disk' in result.output
    assert 'external' in path.read_text()


def test_optional_post_save_test(tmp_path):
    path = tmp_path / 'config.yaml'
    _, transport = run_setup(path,
        '1\nslack\nhttps://hooks.slack.com/SECRET\n\ny\nn\nsave\ny\ny\nexit\n')
    transport.assert_called_once()
    assert transport.call_args.args[0] == 'slack'


def test_symlink_save_refused_without_modifying_target(tmp_path):
    target = tmp_path / 'target.yaml'
    target.write_text('{}\n')
    link = tmp_path / 'config.yaml'
    link.symlink_to(target)
    result, _ = run_setup(link, '2\n1\neth0\nback\nsave\nexit\ndiscard\n')
    assert 'symlink' in result.output
    assert link.is_symlink()
    assert target.read_text() == '{}\n'


def test_failed_save_retains_draft_without_partial_write(tmp_path):
    path = tmp_path / 'config.yaml'
    path.write_text('{}\n')
    with patch('lanfence.cli.save_channels_config_file', side_effect=PermissionError):
        result, _ = run_setup(path, '2\n1\neth0\nback\nsave\ny\nreview\nexit\ndiscard\n')
    assert 'Could not save' in result.output
    assert 'scan.interface (added)' in result.output
    assert path.read_text() == '{}\n'


def test_insecure_permissions_disclosed_before_save(tmp_path):
    path = tmp_path / 'config.yaml'
    path.write_text('{}\n')
    path.chmod(0o644)
    result, _ = run_setup(path, '2\n1\neth0\nback\nsave\nexit\n')
    assert 'restrict this file' in result.output
    assert path.stat().st_mode & 0o777 == 0o600


def test_validation_does_not_leak_credentials(tmp_path):
    path = tmp_path / 'config.yaml'
    path.write_text('alerts:\n  slack:\n    timeout_seconds: SUPER_SECRET\n')
    with pytest.raises(ConfigFileError) as exc:
        load_channels_config_file(path)
    assert 'SUPER_SECRET' not in str(exc.value)


def test_channel_test_failure_does_not_echo_remote_error(tmp_path):
    import urllib.error
    from lanfence.channels import send_channel_test_message
    cfg = Config.model_validate({'alerts': {'slack': {'enabled': True, 'webhook_url': 'https://host/SECRET'}}})
    with patch('lanfence.channels.urllib.request.urlopen', side_effect=urllib.error.URLError('https://host/SECRET')):
        ok, message = send_channel_test_message('slack', cfg)
    assert not ok
    assert 'SECRET' not in message


# --- Web portal section --------------------------------------------------


def test_web_portal_enable_set_password_offers_and_starts(tmp_path):
    path = tmp_path / 'config.yaml'
    with patch('lanfence.web.start_background', return_value='http://192.168.1.5:8080/') as start_mock, \
         patch('lanfence.web.resolve_bind_host', return_value='192.168.1.5'), \
         patch('lanfence.web.detect_active_firewall', return_value=None):
        result, _ = run_setup(
            path, '9\n1\ny\n3\nhunter22\nhunter22\nback\nsave\ny\nexit\n',
        )
    assert 'Web portal starting: http://192.168.1.5:8080/' in result.output
    start_mock.assert_called_once_with(path)
    raw = yaml.safe_load(path.read_text())
    assert raw['web']['enabled'] is True
    assert raw['web']['password_hash']
    assert raw['web']['password_salt']
    assert 'hunter22' not in result.output


def test_web_portal_enable_offers_to_open_firewall_when_active(tmp_path):
    path = tmp_path / 'config.yaml'
    with patch('lanfence.web.start_background', return_value='http://192.168.1.5:8080/'), \
         patch('lanfence.web.resolve_bind_host', return_value='192.168.1.5'), \
         patch('lanfence.web.detect_active_firewall', return_value='ufw'), \
         patch('lanfence.web.allow_port_through_firewall', return_value=(True, 'firewall rule added (ufw)')) as allow_mock:
        result, _ = run_setup(
            path, '9\n1\ny\n3\nhunter22\nhunter22\nback\nsave\ny\ny\nexit\n',
        )
    assert 'ufw firewall is active' in result.output
    assert 'firewall rule added (ufw)' in result.output
    allow_mock.assert_called_once_with('ufw', host='192.168.1.5', port=8080)


def test_web_portal_enable_declining_firewall_prompt_skips_it(tmp_path):
    path = tmp_path / 'config.yaml'
    with patch('lanfence.web.start_background', return_value='http://192.168.1.5:8080/'), \
         patch('lanfence.web.resolve_bind_host', return_value='192.168.1.5'), \
         patch('lanfence.web.detect_active_firewall', return_value='ufw'), \
         patch('lanfence.web.allow_port_through_firewall') as allow_mock:
        result, _ = run_setup(
            path, '9\n1\ny\n3\nhunter22\nhunter22\nback\nsave\nn\ny\nexit\n',
        )
    assert 'ufw firewall is active' in result.output
    allow_mock.assert_not_called()


def test_web_portal_enable_no_firewall_prompt_when_none_detected(tmp_path):
    path = tmp_path / 'config.yaml'
    with patch('lanfence.web.start_background', return_value='http://192.168.1.5:8080/'), \
         patch('lanfence.web.resolve_bind_host', return_value='192.168.1.5'), \
         patch('lanfence.web.detect_active_firewall', return_value=None), \
         patch('lanfence.web.allow_port_through_firewall') as allow_mock:
        result, _ = run_setup(path, '9\n1\ny\n3\nhunter22\nhunter22\nback\nsave\ny\nexit\n')
    assert 'firewall is active' not in result.output
    allow_mock.assert_not_called()


def test_web_portal_enable_without_password_does_not_offer_start(tmp_path):
    path = tmp_path / 'config.yaml'
    with patch('lanfence.web.start_background') as start_mock:
        result, _ = run_setup(path, '9\n1\ny\nback\nsave\nexit\n')
    assert 'cannot start until you set one' in result.output
    start_mock.assert_not_called()


def test_web_portal_declining_start_does_not_call_start_background(tmp_path):
    path = tmp_path / 'config.yaml'
    with patch('lanfence.web.start_background') as start_mock, \
         patch('lanfence.web.resolve_bind_host', return_value='192.168.1.5'), \
         patch('lanfence.web.detect_active_firewall', return_value=None):
        result, _ = run_setup(path, '9\n1\ny\n3\nhunter22\nhunter22\nback\nsave\nn\nexit\n')
    start_mock.assert_not_called()
    assert result.exit_code == 0


def test_web_portal_password_mismatch_leaves_it_unset(tmp_path):
    path = tmp_path / 'config.yaml'
    result, _ = run_setup(path, '9\n3\nhunter1\nhunter2\nback\nexit\n')
    assert 'did not match' in result.output.lower()


def test_web_portal_disable_stops_running_server(tmp_path):
    path = tmp_path / 'config.yaml'
    path.write_text(
        yaml.safe_dump({'web': {'enabled': True, 'password_hash': 'x' * 64, 'password_salt': 'y' * 32}})
    )
    with patch('lanfence.web.stop_server', return_value=True) as stop_mock:
        result, _ = run_setup(path, '9\n1\nn\nback\nsave\nexit\n')
    assert 'Web portal stopped.' in result.output
    stop_mock.assert_called_once()


def test_web_portal_password_change_while_running_notes_restart_needed(tmp_path):
    path = tmp_path / 'config.yaml'
    path.write_text(
        yaml.safe_dump({'web': {'enabled': True, 'password_hash': 'x' * 64, 'password_salt': 'y' * 32}})
    )
    with patch('lanfence.web.is_server_running', return_value=True):
        result, _ = run_setup(path, '9\n3\nnewpassword\nnewpassword\nback\nsave\nexit\n')
    assert "won't see this change until it's restarted" in result.output
