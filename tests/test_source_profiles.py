import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.source_profiles import load_profiles, index_patterns, create_source_folders, describe_profiles


class SourceProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / 'profiles.json'
        self.data = {'version': 1, 'profiles': copy.deepcopy(load_profiles())}

    def tearDown(self):
        self.temp.cleanup()

    def load(self, data):
        self.path.write_text(json.dumps(data))
        return load_profiles(self.path)

    def test_only_lab_namespaces_are_granted_not_rule_hint_patterns(self):
        self.data['profiles']['cloud_defend.alerts']['rule_index_patterns'] = ['logs-*', '*']
        patterns = index_patterns(self.load(self.data))
        self.assertIn('logs-lab-*', patterns)
        self.assertIn('logs-cloud_defend.alerts-lab-*', patterns)
        self.assertNotIn('logs-*', patterns)
        self.assertNotIn('*', patterns)

    def test_path_traversal_wildcards_and_prefix_injection_are_rejected(self):
        for name in ('../cloud_defend.alerts', '/logs/evil', 'UPPER', 'a/b', 'a\\b', 'a*', '.', 'a..b', 'x' * 101):
            data = copy.deepcopy(self.data)
            data['profiles'][name] = data['profiles'].pop('cloud_defend.alerts')
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.load(data)
        for key, value in (('index_prefix', 'logs-*'), ('index_prefix', '.security'), ('dataset', 'other.source')):
            data = copy.deepcopy(self.data)
            data['profiles']['cloud_defend.alerts'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.load(data)

    def test_generic_and_exact_schema_are_required(self):
        for key, value in (('version', True), ('version', 2), ('profiles', []), ('profiles', {})):
            data = copy.deepcopy(self.data)
            data[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.load(data)
        data = copy.deepcopy(self.data)
        del data['profiles']['generic']
        with self.assertRaises(ValueError):
            self.load(data)

    def test_duplicate_json_profile_keys_and_oversized_config_fail(self):
        self.path.write_text('{"version":1,"version":1,"profiles":{}}')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            load_profiles(self.path)
        self.path.write_text(' ' * 65537)
        with self.assertRaisesRegex(ValueError, '64 KiB'):
            load_profiles(self.path)

    def test_bad_guidance_fails_cleanly_without_type_error(self):
        for key, value in (('description', None), ('required_fields', [{}]), ('required_fields', ['@timestamp', '@timestamp']), ('rule_index_patterns', [None]), ('example_query', {'language': [], 'query': 'x'})):
            data = copy.deepcopy(self.data)
            data['profiles']['cloud_defend.alerts'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.load(data)

    def test_directory_creation_never_follows_symlinks_or_removes_logs(self):
        profiles = self.data['profiles']
        (self.root / 'evidence').mkdir()
        (self.root / 'logs').symlink_to(self.root / 'evidence', target_is_directory=True)
        with self.assertRaises(ValueError):
            create_source_folders(self.root, profiles)
        self.assertFalse(list((self.root / 'evidence').iterdir()))
        (self.root / 'logs').unlink()
        create_source_folders(self.root, profiles)
        source_dir = self.root / 'logs/cloud_defend.alerts'
        source_dir.rmdir()
        source_dir.symlink_to(self.root / 'evidence', target_is_directory=True)
        with self.assertRaises(ValueError):
            create_source_folders(self.root, profiles)
        self.assertFalse(list((self.root / 'evidence').iterdir()))

    def test_all_folders_are_validated_before_creation(self):
        (self.root / 'live-logs').mkdir()
        (self.root / 'live-logs/generic').write_text('evidence')
        with self.assertRaises(ValueError):
            create_source_folders(self.root, self.data['profiles'])
        self.assertFalse((self.root / 'logs').exists())
        self.assertEqual((self.root / 'live-logs/generic').read_text(), 'evidence')

    def test_guidance_shows_exact_example_but_does_not_claim_detection(self):
        text = describe_profiles(self.data['profiles'], 'cloud_defend.alerts')
        self.assertIn('logs/cloud_defend.alerts/', text)
        self.assertIn('logs-cloud_defend.alerts-lab-YYYY.MM.dd', text)
        self.assertIn('event.kind:alert and event.module:cloud_defend', text)
        self.assertIn('통합 패키지를 설치하거나', text)
        with self.assertRaisesRegex(ValueError, '등록되지 않은 소스'):
            describe_profiles(self.data['profiles'], 'missing')


if __name__ == '__main__':
    unittest.main()
