"""Archive safety and transactional refresh tests; no external network or SIEM."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("sync_labs", Path(__file__).resolve().parents[1] / "scripts" / "sync_labs.py")
labs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(labs)
SHA1 = "a" * 40
SHA2 = "b" * 40


def archive_bytes(revision, entries=None):
    output = io.BytesIO()
    files = {"README.md": b"# Elastic Labs\n",
             "notebooks/search/example.ipynb": b"{}",
             "notebooks/search/_nbtest.teardown.ipynb": b"{}",
             "supporting-blog-content/security-labs/collector/README.md": b"# Collector",
             "supporting-blog-content/security-labs/advisory/agent-prompt.md": b"# Prompt",
             "supporting-blog-content/observability-labs/monitor/example.ipynb": b"{}",
             "example-apps/chatbot-rag-app/README.md": b"# Chatbot",
             "example-apps/chatbot-rag-app/app.py": b"raise RuntimeError('must not run')"}
    with tarfile.open(fileobj=output, mode="w:gz") as bundle:
        for name, payload in files.items():
            info = tarfile.TarInfo(f"elastic-labs-{revision}/{name}")
            info.size = len(payload)
            info.mode = 0o777
            bundle.addfile(info, io.BytesIO(payload))
        for name, member_type, linkname in entries or []:
            info = tarfile.TarInfo(name)
            info.type = member_type
            info.linkname = linkname
            bundle.addfile(info)
    return output.getvalue()


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "cache"

    def fixture_sync(self, revision=SHA1, ref="main", payload=None):
        payload = archive_bytes(revision) if payload is None else payload

        def download(actual_revision, target):
            self.assertEqual(actual_revision, revision)
            target.write_bytes(payload)
            return hashlib.sha256(payload).hexdigest()

        with mock.patch.object(labs, "resolve_revision", return_value=revision), mock.patch.object(labs, "download_archive", side_effect=download):
            return labs.sync(self.root, ref=ref)

    def test_catalog_classifies_explicit_namespaces_and_records_provenance(self):
        manifest = self.fixture_sync()
        catalog = json.loads((self.root / "catalog.json").read_text())
        self.assertEqual(manifest["revision"], catalog["revision"])
        self.assertEqual(manifest["example_count"], 5)
        self.assertEqual([e["category"] for e in catalog["entries"][:2]], ["security", "security"])
        self.assertTrue(all(e["auto_execute"] is False for e in catalog["entries"]))
        self.assertTrue(all(e["compatibility"] == "not-validated" for e in catalog["entries"]))
        self.assertTrue(all(f"/blob/{SHA1}/" in e["url"] for e in catalog["entries"]))
        self.assertTrue(any(e["category"] == "observability" for e in catalog["entries"]))
        self.assertFalse(any("_nbtest" in e["path"] for e in catalog["entries"]))
        self.assertEqual((self.root / "source" / "README.md").stat().st_mode & 0o777, 0o644)

    def test_refresh_switches_source_catalog_manifest_together(self):
        self.fixture_sync()
        original_pointer = os.readlink(self.root / "current")
        self.fixture_sync(SHA2)
        self.assertNotEqual(os.readlink(self.root / "current"), original_pointer)
        self.assertEqual(labs.cached_manifest(self.root, "main")["revision"], SHA2)
        self.assertEqual(json.loads((self.root / "catalog.json").read_text())["revision"], SHA2)
        self.assertEqual(len(list((self.root / ".releases").iterdir())), 1)

    def test_same_revision_still_resolves_main_but_skips_download(self):
        self.fixture_sync()
        with mock.patch.object(labs, "resolve_revision", return_value=SHA1) as resolve, mock.patch.object(labs, "download_archive") as download:
            labs.sync(self.root)
        resolve.assert_called_once_with("main")
        download.assert_not_called()

    def test_network_failure_does_not_silently_fall_back(self):
        self.fixture_sync()
        old_pointer = os.readlink(self.root / "current")
        with mock.patch.object(labs, "resolve_revision", side_effect=OSError("offline")):
            with self.assertRaisesRegex(OSError, "offline"):
                labs.sync(self.root)
        self.assertEqual(old_pointer, os.readlink(self.root / "current"))

    def test_partial_archive_failure_keeps_last_complete_snapshot(self):
        self.fixture_sync()
        old_pointer = os.readlink(self.root / "current")
        payload = archive_bytes(SHA2, [(f"elastic-labs-{SHA2}/../../outside", tarfile.REGTYPE, "")])
        with self.assertRaisesRegex(labs.SyncError, "Unsafe archive path"):
            self.fixture_sync(SHA2, payload=payload)
        self.assertEqual(old_pointer, os.readlink(self.root / "current"))
        self.assertEqual(labs.cached_manifest(self.root, "main")["revision"], SHA1)
        self.assertEqual(len(list((self.root / ".releases").iterdir())), 1)
        self.assertFalse((self.root.parent / "outside").exists())

    def test_pointer_publish_failure_restores_old_selection(self):
        self.fixture_sync()
        old_pointer = os.readlink(self.root / "current")
        with mock.patch.object(labs.os, "replace", side_effect=OSError("disk failed")):
            with self.assertRaisesRegex(OSError, "disk failed"):
                self.fixture_sync(SHA2)
        self.assertEqual(old_pointer, os.readlink(self.root / "current"))
        self.assertEqual(len(list((self.root / ".releases").iterdir())), 1)

    def test_explicit_offline_does_not_access_network_and_checks_pin(self):
        self.fixture_sync()
        with mock.patch.object(labs, "request", side_effect=AssertionError("network used")):
            self.assertEqual(labs.sync(self.root, offline=True)["revision"], SHA1)
            self.assertEqual(labs.sync(self.root, ref=SHA1, offline=True)["revision"], SHA1)
            with self.assertRaisesRegex(labs.SyncError, "does not match"):
                labs.sync(self.root, ref=SHA2, offline=True)

    def test_offline_requires_matching_complete_cache(self):
        with self.assertRaisesRegex(labs.SyncError, "No valid cache"):
            labs.sync(self.root, offline=True)
        self.fixture_sync()
        (self.root / "catalog.json").write_text('{"revision":"wrong"}')
        with self.assertRaisesRegex(labs.SyncError, "No valid cache"):
            labs.sync(self.root, offline=True)

    def test_full_pin_avoids_moving_branch_resolution(self):
        with mock.patch.object(labs, "request", side_effect=AssertionError("network used")):
            self.assertEqual(labs.resolve_revision(SHA1), SHA1)

    def test_branch_ref_is_encoded_and_validated(self):
        response = io.BytesIO(json.dumps({"sha": SHA2}).encode())
        with mock.patch.object(labs, "request", return_value=response) as request:
            self.assertEqual(labs.resolve_revision("release/next"), SHA2)
        self.assertTrue(request.call_args.args[0].endswith("release%2Fnext"))
        with self.assertRaises(labs.SyncError):
            labs.resolve_revision("main\ninvalid")

    def test_archive_rejects_traversal_links_devices_and_wrong_root(self):
        cases = [
            (f"elastic-labs-{SHA1}/../escape", tarfile.REGTYPE, ""),
            (f"elastic-labs-{SHA1}/x/../../escape", tarfile.REGTYPE, ""),
            ("/absolute", tarfile.REGTYPE, ""),
            (f"elastic-labs-{SHA1}/a\\b", tarfile.REGTYPE, ""),
            ("unrelated/README.md", tarfile.REGTYPE, ""),
            (f"elastic-labs-{SHA1}/symlink", tarfile.SYMTYPE, "../../outside"),
            (f"elastic-labs-{SHA1}/hardlink", tarfile.LNKTYPE, "../../outside"),
            (f"elastic-labs-{SHA1}/device", tarfile.CHRTYPE, ""),
            (f"elastic-labs-{SHA1}/fifo", tarfile.FIFOTYPE, ""),
        ]
        for i, entry in enumerate(cases):
            with self.subTest(entry=entry):
                archive = Path(self.temp.name) / f"{i}.tgz"
                archive.write_bytes(archive_bytes(SHA1, [entry]))
                with self.assertRaises(labs.SyncError):
                    labs.extract_archive(archive, Path(self.temp.name) / f"source-{i}", SHA1)

    def test_archive_limits_are_enforced(self):
        for setting in ("MAX_FILE_BYTES", "MAX_EXTRACTED_BYTES", "MAX_ENTRIES"):
            with self.subTest(setting=setting), mock.patch.object(labs, setting, 1):
                archive = Path(self.temp.name) / f"{setting}.tgz"
                archive.write_bytes(archive_bytes(SHA1))
                with self.assertRaises(labs.SyncError):
                    labs.extract_archive(archive, Path(self.temp.name) / setting, SHA1)

    def test_download_limit_and_hash(self):
        payload = b"archive bytes"
        target = Path(self.temp.name) / "archive.tgz"
        with mock.patch.object(labs, "request", return_value=io.BytesIO(payload)):
            self.assertEqual(labs.download_archive(SHA1, target), hashlib.sha256(payload).hexdigest())
        target.unlink()
        with mock.patch.object(labs, "request", return_value=io.BytesIO(payload)), mock.patch.object(labs, "MAX_ARCHIVE_BYTES", 1):
            with self.assertRaises(labs.SyncError):
                labs.download_archive(SHA1, target)

    def test_unmanaged_paths_are_never_replaced(self):
        self.root.mkdir()
        (self.root / "source").mkdir()
        (self.root / "source" / "myfile").write_text("keep")
        with self.assertRaisesRegex(labs.SyncError, "unmanaged"):
            self.fixture_sync()
        self.assertEqual((self.root / "source" / "myfile").read_text(), "keep")

    def test_cache_root_symlink_is_rejected(self):
        actual = Path(self.temp.name) / "actual"
        actual.mkdir()
        self.root.symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(labs.SyncError, "must not be a symlink"):
            self.fixture_sync()


if __name__ == "__main__":
    unittest.main()
