import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lab', REPO / 'builder.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        shutil.copy(REPO / '.env.example', self.root)
        self.patcher = patch.object(lab, 'ROOT', self.root)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.temp.cleanup()

    def test_init_persists_distinct_secrets_and_does_not_overwrite_existing_env(self):
        first = lab.init()
        self.assertEqual(len({first[key] for key in lab.SECRET_KEYS}), 6)
        self.assertEqual((self.root / '.env').stat().st_mode & 0o777, 0o600)
        self.assertEqual(first, lab.init())

    def test_invalid_credentials_and_ports_fail_locally(self):
        lab.init()
        env = self.root / '.env'
        env.write_text(env.read_text().replace('ES_PORT=9200', 'ES_PORT=99999'))
        with self.assertRaisesRegex(ValueError, 'ES_PORT'):
            lab.init()

    def test_config_does_not_execute_env_content(self):
        env = self.root / 'malicious.env'
        env.write_text('VALUE=$(touch bad)\n')
        self.assertEqual(lab.read_env(env)['VALUE'], '$(touch bad)')
        self.assertFalse((self.root / 'bad').exists())

    def test_specific_bind_address_is_in_certificate_san(self):
        lab.init()
        env = self.root / '.env'
        env.write_text(env.read_text().replace('BIND_HOST=0.0.0.0', 'BIND_HOST=192.0.2.30'))
        lab.init()
        spec = json.loads((self.root / '.state/instances.yml').read_text())
        self.assertIn('192.0.2.30', spec['instances'][0]['ip'])

    def test_failed_upstream_sync_does_not_start_any_runtime(self):
        with patch.object(lab, 'sync', side_effect=RuntimeError('offline')), patch.object(lab, 'compose') as compose:
            with self.assertRaises(RuntimeError):
                lab.up(types.SimpleNamespace(offline=False, ref=None, trial=False))
            compose.assert_not_called()

    def test_bootstrap_error_prevents_logstash_start(self):
        def compose(*args, **kwargs):
            if 'bootstrap' in args:
                raise subprocess.CalledProcessError(1, args)
        with patch.object(lab, 'sync'), patch.object(lab, 'compose', side_effect=compose) as call:
            with self.assertRaises(subprocess.CalledProcessError):
                lab.up(types.SimpleNamespace(offline=True, ref=None, trial=False))
            self.assertFalse(any('logstash' in item.args for item in call.call_args_list))

    def test_compose_uses_checked_env_not_exported_overrides(self):
        lab.init()
        with patch.dict(os.environ, {'COMPOSE_PROJECT_NAME': 'unrelated-project', 'ELASTIC_PASSWORD': 'override'}), patch.object(lab, 'run') as run:
            lab.compose('config', '--quiet')
            self.assertNotIn('COMPOSE_PROJECT_NAME', run.call_args.kwargs['env'])
            self.assertNotIn('ELASTIC_PASSWORD', run.call_args.kwargs['env'])

    def test_trial_flag_reaches_both_bootstrap_phases_without_changing_env(self):
        lab.init()
        before = (self.root / '.env').read_bytes()
        with patch.object(lab, 'sync'), patch.object(lab, 'compose') as compose, \
             patch.object(lab, 'request', return_value={'license': {'type': 'trial', 'status': 'active'}}), \
             patch('builtins.print'):
            lab.up(types.SimpleNamespace(offline=False, ref=None, trial=True))
        phases = [call for call in compose.call_args_list if 'auth' in call.args or 'bootstrap' in call.args]
        self.assertEqual(len(phases), 2)
        self.assertTrue(all(call.kwargs['overrides'] == {'LICENSE_MODE': 'trial'} for call in phases))
        kibana = next(call for call in compose.call_args_list if 'kibana' in call.args)
        self.assertIn('--force-recreate', kibana.args)
        self.assertEqual(before, (self.root / '.env').read_bytes())

    def test_configured_trial_mode_is_used_without_flag(self):
        env = lab.init()
        env['LICENSE_MODE'] = 'trial'
        with patch.object(lab, 'sync'), patch.object(lab, 'compose') as compose, \
             patch.object(lab, 'request', return_value={'license': {'type': 'trial', 'status': 'active'}}), \
             patch('builtins.print'):
            lab.up(types.SimpleNamespace(offline=False, ref=None, trial=False), env=env)
        bootstrap = next(call for call in compose.call_args_list if 'bootstrap' in call.args)
        self.assertEqual(bootstrap.kwargs['overrides'], {'LICENSE_MODE': 'trial'})

    def test_version_command_does_not_initialize_or_start_lab(self):
        with patch.object(lab.sys, 'argv', ['builder.py', 'version', '--offline']), \
             patch.object(lab, 'report_latest') as report, patch.object(lab, 'compose') as compose:
            lab.main()
        self.assertFalse((self.root / '.env').exists())
        compose.assert_not_called()
        self.assertTrue(report.call_args.kwargs['offline'])
        self.assertTrue(report.call_args.kwargs['force'])

    def test_version_skip_flag_does_not_make_release_request(self):
        with patch.object(lab.sys, 'argv', ['builder.py', '--no-version-check', 'init']), \
             patch.object(lab, 'report_latest') as report, patch('builtins.print'):
            lab.main()
        report.assert_not_called()


if __name__ == '__main__':
    unittest.main()
