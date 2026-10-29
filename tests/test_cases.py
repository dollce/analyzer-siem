from concurrent.futures import ThreadPoolExecutor
import fnmatch
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.cases import init_case, load_cases, ensure_registry, case_index_patterns, MAX_CASES
from scripts.source_profiles import load_profiles


class CaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / '.cases/registry.json'
        self.profiles = load_profiles()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, data):
        self.path.parent.mkdir(exist_ok=True)
        self.path.write_text(json.dumps(data))

    def test_init_creates_both_trees_and_preserves_evidence_on_repeat(self):
        patterns = init_case(self.root, 'incident001', self.profiles)
        for base in ('logs', 'live-logs'):
            for source in self.profiles:
                self.assertEqual(list((self.root / base / 'incident001' / source).iterdir()), [])
        evidence = self.root / 'logs/incident001/cloud_defend.alerts/evidence.ndjson'
        evidence.write_bytes(b'original evidence\x00')
        before = self.path.read_bytes()
        init_case(self.root, 'incident001', self.profiles)
        self.assertEqual(evidence.read_bytes(), b'original evidence\x00')
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(load_cases(self.path, self.profiles), ['incident001'])
        self.assertIn('logs-lab-case_incident001-*', patterns)
        self.assertEqual(len(patterns), len(self.profiles))
        self.assertFalse((self.root / '.env').exists())
        self.assertFalse((self.root / '.state').exists())

    def test_prepare_does_not_infer_cases_from_old_directories(self):
        (self.root / 'logs/oldcase/cloud_defend.alerts').mkdir(parents=True)
        self.assertEqual(ensure_registry(self.root, self.profiles), [])
        self.assertEqual(load_cases(self.path, self.profiles), [])

    def test_patterns_do_not_overlap_similar_case_ids(self):
        for case in ('a', 'a_1', 'a1'):
            patterns = case_index_patterns(self.profiles, case)
            for other in ('a', 'a_1', 'a1'):
                for source in self.profiles.values():
                    index = f"{source['index_prefix']}-case_{other}-2026.10.29"
                    self.assertEqual(any(fnmatch.fnmatchcase(index, pattern) for pattern in patterns), case == other)

    def test_invalid_or_source_colliding_names_do_not_create_files(self):
        for name in ('../escape', 'Case', 'case-1', 'a/b', 'a.b', '', '한글', 'a' * 65, 'generic', None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                init_case(self.root, name, self.profiles)
            self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_registry_is_rejected_before_case_folders(self):
        for data in ({'version': True, 'cases': []}, {'version': 1, 'cases': ['a', 'a']},
                     {'version': 1, 'cases': ['generic']}, {'version': 1, 'cases': [{}]},
                     {'version': 1, 'cases': 'a'}, {'version': 1, 'cases': ['a'], 'other': 1}):
            self.write(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                init_case(self.root, 'incident001', self.profiles)
            self.assertFalse((self.root / 'logs').exists())

    def test_duplicate_keys_and_large_registry_are_rejected(self):
        self.path.parent.mkdir()
        for raw in ('{"version":1,"cases":[],"cases":[]}', ' ' * 65537):
            self.path.write_text(raw)
            with self.assertRaises(ValueError):
                load_cases(self.path, self.profiles)

    def test_input_symlinks_and_file_collisions_do_not_escape_or_partially_create(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.root / 'live-logs').mkdir()
        (self.root / 'live-logs/incident001').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            init_case(self.root, 'incident001', self.profiles)
        self.assertFalse((self.root / 'logs').exists())
        self.assertEqual(list(outside.iterdir()), [])
        (self.root / 'live-logs/incident001').unlink()
        (self.root / 'live-logs/incident001').write_text('evidence')
        with self.assertRaises(ValueError):
            init_case(self.root, 'incident001', self.profiles)
        self.assertFalse((self.root / 'logs').exists())

    def test_registry_symlink_is_rejected(self):
        self.path.parent.mkdir()
        original = self.root / 'original.json'
        original.write_text('{"version":1,"cases":[]}')
        self.path.symlink_to(original)
        with self.assertRaises(ValueError):
            init_case(self.root, 'incident001', self.profiles)
        self.assertEqual(original.read_text(), '{"version":1,"cases":[]}')

    def test_failed_publish_retains_existing_registry_and_retry_succeeds(self):
        init_case(self.root, 'a', self.profiles)
        before = self.path.read_bytes()
        with patch('scripts.cases.os.replace', side_effect=OSError('disk error')):
            with self.assertRaises(OSError):
                init_case(self.root, 'b', self.profiles)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.path.parent.glob('.registry-*')), [])
        init_case(self.root, 'b', self.profiles)
        self.assertEqual(load_cases(self.path, self.profiles), ['a', 'b'])

    def test_parallel_registration_does_not_lose_cases(self):
        names = [f'case{i}' for i in range(6)]
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(lambda name: init_case(self.root, name, self.profiles), names))
        self.assertEqual(load_cases(self.path, self.profiles), names)

    def test_registry_limit_allows_idempotent_existing_case(self):
        self.write({'version': 1, 'cases': [f'case{i}' for i in range(MAX_CASES)]})
        with self.assertRaises(ValueError):
            init_case(self.root, 'newcase', self.profiles)
        self.assertFalse((self.root / 'logs').exists())
        init_case(self.root, 'case0', self.profiles)
        self.assertEqual(len(load_cases(self.path, self.profiles)), MAX_CASES)


if __name__ == '__main__':
    unittest.main()
