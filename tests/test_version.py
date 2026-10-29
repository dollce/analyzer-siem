import importlib.util
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('check_version', Path(__file__).resolve().parents[1] / 'scripts/check_version.py')
version = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(version)


def release(number='9.5.5'):
    return {'version': number, 'url': version.RELEASE_URL + number, 'published_at': '2026-10-06T14:01:58Z'}


def payload(number='9.5.5', **changes):
    return {'draft': False, 'prerelease': False, 'tag_name': 'v' + number,
            'html_url': version.RELEASE_URL + number, 'published_at': '2026-10-06T14:01:58Z', **changes}


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cache = Path(self.temp.name)
        self.output = io.StringIO()
        self.now = 1800000000.0
        self.clock = patch.object(version.time, 'time', return_value=self.now)
        self.clock.start()

    def tearDown(self):
        self.clock.stop()
        self.temp.cleanup()

    def report(self, current='9.5.5', **kwargs):
        return version.report_latest(current, cache_dir=self.cache, stream=self.output, **kwargs)

    def test_new_release_notifies_without_touching_other_files(self):
        sentinel = self.cache / '.env'
        sentinel.write_text('STACK_VERSION=9.5.5\n')
        with patch.object(version, 'bounded_fetch', return_value=release('9.6.0')):
            result = self.report()
        self.assertTrue(result['newer'])
        self.assertEqual(result['status'], 'fresh')
        self.assertIn('No automatic upgrade', self.output.getvalue())
        self.assertEqual(sentinel.read_text(), 'STACK_VERSION=9.5.5\n')

    def test_semantic_order_is_numeric(self):
        with patch.object(version, 'bounded_fetch', return_value=release('9.10.0')):
            self.assertTrue(self.report('9.9.99')['newer'])

    def test_current_or_ahead_version_never_suggests_downgrade(self):
        with patch.object(version, 'bounded_fetch', return_value=release()):
            self.assertFalse(self.report('9.5.5')['newer'])
            self.assertFalse(self.report('10.0.0')['newer'])
        self.assertNotIn('NOTICE:', self.output.getvalue())

    def test_prerelease_draft_snapshot_and_noncanonical_versions_are_rejected(self):
        candidates = [payload(prerelease=True), payload(draft=True), payload('9.6.0-SNAPSHOT'),
                      payload('9.6.0-rc1'), payload('09.6.0'), payload(published_at=None),
                      payload(html_url='https://example.invalid/release')]
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(version.VersionCheckError):
                version.parse_release(candidate)

    def test_parser_rejects_malformed_response(self):
        for value in (None, [], {}, payload(tag_name=7), payload(published_at='not-a-date')):
            with self.subTest(value=value), self.assertRaises(version.VersionCheckError):
                version.parse_release(value)

    def test_successful_cache_used_for_24_hours(self):
        version.write_cache(self.cache, release('9.6.0'), self.now - 60)
        with patch.object(version, 'bounded_fetch') as fetch:
            self.assertEqual(self.report()['status'], 'cached')
            fetch.assert_not_called()
        self.assertIn('cached for up to 24h', self.output.getvalue())

    def test_expired_cache_refreshed(self):
        version.write_cache(self.cache, release(), self.now - version.CACHE_TTL_SECONDS)
        with patch.object(version, 'bounded_fetch', return_value=release('9.6.0')) as fetch:
            self.assertEqual(self.report()['latest'], '9.6.0')
            fetch.assert_called_once()

    def test_force_bypasses_fresh_cache(self):
        version.write_cache(self.cache, release(), self.now)
        with patch.object(version, 'bounded_fetch', return_value=release('9.6.0')) as fetch:
            self.assertEqual(self.report(force=True)['status'], 'fresh')
            fetch.assert_called_once()

    def test_offline_never_uses_network_even_with_force(self):
        with patch.object(version, 'bounded_fetch') as fetch:
            self.assertEqual(self.report(offline=True, force=True)['status'], 'offline')
            version.write_cache(self.cache, release('9.6.0'), self.now - 7 * version.CACHE_TTL_SECONDS)
            self.assertEqual(self.report(offline=True, force=True)['status'], 'offline-cache')
            fetch.assert_not_called()
        self.assertIn('latest status unverified', self.output.getvalue())

    def test_failure_preserves_last_success_and_labels_stale(self):
        version.write_cache(self.cache, release('9.6.0'), self.now - version.CACHE_TTL_SECONDS)
        before = (self.cache / 'latest.json').read_bytes()
        with patch.object(version, 'bounded_fetch', side_effect=version.VersionCheckError('outage')):
            self.assertEqual(self.report()['status'], 'stale-cache')
        self.assertEqual(before, (self.cache / 'latest.json').read_bytes())
        self.assertIn('lookup failed', self.output.getvalue())

    def test_failure_without_cache_is_nonfatal(self):
        with patch.object(version, 'bounded_fetch', side_effect=OSError('offline')):
            self.assertEqual(self.report()['status'], 'unavailable')
        self.assertFalse((self.cache / 'latest.json').exists())

    def test_corrupt_cache_does_not_block_good_lookup(self):
        for content in ('not json', '{}' , 'x' * (version.MAX_CACHE_BYTES + 1)):
            (self.cache / 'latest.json').write_text(content)
            with patch.object(version, 'bounded_fetch', return_value=release()):
                self.assertEqual(self.report()['status'], 'fresh')

    def test_future_or_nonfinite_cache_timestamp_is_ignored(self):
        for stamp in (self.now + 1, float('nan'), float('inf'), True):
            version.write_cache(self.cache, release(), stamp)
            self.assertIsNone(version.read_cache(self.cache, self.now))

    def test_unwritable_cache_is_nonfatal(self):
        with patch.object(version, 'bounded_fetch', return_value=release()), patch.object(version, 'write_cache', side_effect=PermissionError()):
            self.assertEqual(self.report()['status'], 'fresh')

    def test_atomic_write_failure_preserves_cache_and_cleans_temp(self):
        version.write_cache(self.cache, release(), self.now)
        before = (self.cache / 'latest.json').read_bytes()
        with patch.object(version.os, 'replace', side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):
                version.write_cache(self.cache, release('9.6.0'), self.now)
        self.assertEqual(before, (self.cache / 'latest.json').read_bytes())
        self.assertEqual([path.name for path in self.cache.iterdir()], ['latest.json'])

    def test_payload_limit_is_enforced(self):
        response = io.BytesIO(b'x' * (version.MAX_RESPONSE_BYTES + 1))
        with patch.object(version.urllib.request, 'urlopen', return_value=response):
            with self.assertRaises(version.VersionCheckError):
                version.fetch_release()

    def test_fetch_uses_official_release_api_and_parses_stable_release(self):
        response = io.BytesIO(json.dumps(payload()).encode())
        with patch.object(version.urllib.request, 'urlopen', return_value=response) as fetch:
            self.assertEqual(version.fetch_release()['version'], '9.5.5')
        self.assertEqual(fetch.call_args.args[0].full_url, version.SOURCE_URL)
        self.assertLessEqual(fetch.call_args.kwargs['timeout'], 3)

    def test_total_wait_is_bounded_without_late_cache_write(self):
        release_worker = threading.Event()
        def delayed():
            release_worker.wait(1)
            return release('9.6.0')
        try:
            with patch.object(version, 'TIMEOUT_SECONDS', 0.02), patch.object(version, 'fetch_release', side_effect=delayed):
                start = time.monotonic()
                self.assertEqual(self.report()['status'], 'unavailable')
                self.assertLess(time.monotonic() - start, 0.5)
                self.assertFalse((self.cache / 'latest.json').exists())
        finally:
            release_worker.set()


if __name__ == '__main__':
    unittest.main()
