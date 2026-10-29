import importlib.util
from concurrent.futures import ThreadPoolExecutor
import io
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import threading
import unittest
from unittest.mock import Mock, patch
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bootstrap", ROOT / "scripts/bootstrap.py")
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class FakeAPI:
    def __init__(self, *, index_exists=False, license_type="basic"):
        self.calls = []
        self.index_exists = index_exists
        self.license_type = license_type
        self.license_status = "active"
        self.trial_expiry = 4102444800000
        self.overrides = {}

    def request(self, method, path, payload=None, **kwargs):
        self.calls.append((method, path, payload, kwargs))
        if (method, path) in self.overrides:
            value = self.overrides[(method, path)]
            if isinstance(value, Exception):
                raise value
            return value
        if path.startswith("/_cluster/health"):
            return {"status": "yellow", "timed_out": False}
        if path == "/_license":
            result = {"type": self.license_type, "status": self.license_status}
            if self.license_type == "trial":
                result["expiry_date_in_millis"] = self.trial_expiry
            return {"license": result}
        if path == "/_license/trial_status":
            return {"eligible_to_start_trial": True}
        if path == "/_license/start_trial?acknowledge=true":
            self.license_type = "trial"
            return {"acknowledged": True, "trial_was_started": True}
        if path == "/api/status":
            return {"status": {"overall": {"level": "available"}}}
        if path == "/api/data_views/data_view":
            return {"data_view": {"id": payload["data_view"]["id"]}}
        if path == "/api/detection_engine/index" and method == "GET":
            return {"name": ".siem-signals-default"} if self.index_exists else {"_http_status": 404}
        if path == "/api/detection_engine/index" and method == "POST":
            self.index_exists = True
        if path == "/api/detection_engine/rules/prepackaged":
            return dict.fromkeys(("rules_installed", "rules_updated", "timelines_installed", "timelines_updated"), 0)
        return {"acknowledged": True}


class BootstrapTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.labs = Path(self.temp.name)
        (self.labs / ".sync.lock").touch(mode=0o600)
        self.revision = "a" * 40
        self.manifest = {"schema_version": 1, "repository": "https://github.com/elastic/elastic-labs",
                         "revision": self.revision, "synchronized_at": "2026-10-29T00:00:00Z"}
        self.catalog = {**self.manifest, "entries": [{
            "title": "Security notebook", "category": "security", "path": "security/example.ipynb",
            "url": f"https://github.com/elastic/elastic-labs/blob/{self.revision}/security/example.ipynb",
            "auto_execute": False, "compatibility": "not-validated",
        }]}
        self.write_catalog()

    def write_catalog(self):
        (self.labs / "manifest.json").write_text(json.dumps(self.manifest))
        (self.labs / "catalog.json").write_text(json.dumps(self.catalog))

    def configure(self, es=None, kibana=None, **kwargs):
        return bootstrap.configure(es or FakeAPI(), kibana or FakeAPI(),
                                   ROOT / "config/elasticsearch", self.labs, **kwargs)

    def test_auth_role_is_scoped_to_lab_indices_and_no_superuser(self):
        es = FakeAPI()
        bootstrap.auth_setup(es, "kibana-test", "logstash-test")
        role = next(call[2] for call in es.calls if call[1].startswith("/_security/role/"))
        self.assertEqual(role["cluster"], ["monitor"])
        expected = bootstrap.profile_patterns(ROOT / "config/source-profiles.json")
        self.assertEqual(role["indices"][0]["names"], expected)
        self.assertIn("logs-lab-*", expected)
        self.assertIn("logs-cloud_defend.alerts-lab-*", expected)
        self.assertNotIn("logs-*", expected)
        self.assertIn("auto_configure", role["indices"][0]["privileges"])
        user = next(call[2] for call in es.calls if call[1] == "/_security/user/logstash_internal")
        self.assertEqual(user["roles"], ["lab_logstash_writer"])

    def test_reconfigure_upserts_same_resources_and_preserves_detection_index(self):
        es, kibana = FakeAPI(), FakeAPI()
        first = self.configure(es, kibana)
        second = self.configure(es, kibana)
        self.assertEqual(first, second)
        created_indices = [call for call in kibana.calls if call[:2] == ("POST", "/api/detection_engine/index")]
        self.assertEqual(len(created_indices), 1)
        objects = [call[1] for call in kibana.calls if "/api/saved_objects/" in call[1]]
        self.assertEqual(len(objects), 4)
        self.assertEqual(len(set(objects)), 2)
        self.assertTrue(all(path.endswith("?overwrite=true") for path in objects))
        self.assertFalse(any("_bulk_action" in call[1] or "/_bulk" in call[1] for call in kibana.calls + es.calls))

    def test_template_installed_after_pipeline_and_before_view(self):
        es, kibana = FakeAPI(), FakeAPI()
        result = self.configure(es, kibana)
        paths = [call[1] for call in es.calls]
        self.assertLess(paths.index("/_ingest/pipeline/lab-ingest"), paths.index("/_index_template/logs-lab"))
        self.assertEqual(result["license"], "basic")
        patterns = bootstrap.profile_patterns(ROOT / "config/source-profiles.json")
        template = next(call[2] for call in es.calls if call[1] == "/_index_template/logs-lab")
        self.assertEqual(template["index_patterns"], patterns)
        data_views = [call[2] for call in kibana.calls if call[1] == "/api/data_views/data_view"]
        self.assertEqual(len(data_views), 2)
        for view in data_views:
            self.assertEqual(view["data_view"]["title"].split(","), patterns)
            self.assertTrue(view["data_view"]["allowNoIndex"])
            self.assertTrue(view["override"])
        self.assertEqual([(view["data_view"]["id"], view["data_view"]["timeFieldName"]) for view in data_views],
                         [("lab-logs", "@timestamp"), ("lab-logs-ingested", "event.ingested")])
        default = next(call[2] for call in kibana.calls if call[1] == "/api/data_views/default")
        self.assertEqual(default["data_view_id"], "lab-logs")
        self.assertEqual(result["ingest_data_view"], "lab-logs-ingested")

    def test_invalid_profiles_fail_before_auth_or_configure_remote_access(self):
        profiles = self.labs / "source-profiles.json"
        for value in ({"version": 1, "profiles": {}}, {"version": 99, "profiles": {}}, "malformed"):
            profiles.write_text(json.dumps(value))
            for phase in ("auth", "configure"):
                with self.subTest(value=value, phase=phase):
                    es, kibana = FakeAPI(), FakeAPI()
                    with self.assertRaisesRegex(bootstrap.SetupError, "Invalid source profiles"):
                        if phase == "auth":
                            bootstrap.auth_setup(es, "kibana-test", "logstash-test",
                                                 license_mode="trial", profiles_path=profiles)
                        else:
                            self.configure(es, kibana, license_mode="trial", profiles_path=profiles)
                    self.assertEqual(es.calls + kibana.calls, [])

    def test_missing_profiles_fail_before_trial_activation(self):
        es = FakeAPI()
        with self.assertRaisesRegex(bootstrap.SetupError, "Invalid source profiles"):
            bootstrap.auth_setup(es, "kibana-test", "logstash-test", license_mode="trial",
                                 profiles_path=self.labs / "missing.json")
        self.assertEqual(es.calls, [])

    def test_auth_and_template_and_views_use_same_custom_profile_set(self):
        document = bootstrap.read_json(ROOT / "config/source-profiles.json")
        document["profiles"] = {name: document["profiles"][name]
                                for name in ("generic", "cloud_defend.alerts")}
        path = self.labs / "source-profiles.json"
        path.write_text(json.dumps(document))
        es, kibana = FakeAPI(), FakeAPI()
        bootstrap.auth_setup(es, "kibana-test", "logstash-test", profiles_path=path)
        self.configure(es, kibana, profiles_path=path)
        expected = ["logs-lab-*", "logs-cloud_defend.alerts-lab-*"]
        role = next(call[2] for call in es.calls if call[1] == "/_security/role/lab_logstash_writer")
        template = next(call[2] for call in es.calls if call[1] == "/_index_template/logs-lab")
        self.assertEqual(role["indices"][0]["names"], expected)
        self.assertEqual(template["index_patterns"], expected)
        for call in kibana.calls:
            if call[1] == "/api/data_views/data_view":
                self.assertEqual(call[2]["data_view"]["title"], ",".join(expected))
        # Bootstrap creates no ordinary log indices or events to hide empty-index warnings.
        self.assertFalse(any(call[1].startswith("/logs-") or call[1].endswith("/_doc") for call in es.calls))

    def test_bad_data_view_response_does_not_set_default_or_configure_rules(self):
        kibana = FakeAPI()
        kibana.overrides[("POST", "/api/data_views/data_view")] = {"data_view": {"id": "unexpected"}}
        with self.assertRaisesRegex(bootstrap.SetupError, "expected data view ID"):
            self.configure(kibana=kibana)
        self.assertFalse(any(call[1] == "/api/data_views/default" or "/api/detection_engine/" in call[1]
                             for call in kibana.calls))

    def test_trial_is_refused_before_any_remote_mutation(self):
        es, kibana = FakeAPI(license_type="trial"), FakeAPI()
        with self.assertRaisesRegex(bootstrap.SetupError, "Basic license"):
            self.configure(es, kibana)
        self.assertTrue(all(call[0] == "GET" for call in es.calls + kibana.calls))

    def test_trial_activation_precedes_service_credentials_and_is_reverified_in_configure(self):
        es, kibana = FakeAPI(), FakeAPI()
        auth_result = bootstrap.auth_setup(es, "kibana-test", "logstash-test", license_mode="trial")
        result = self.configure(es, kibana, license_mode="trial")
        paths = [call[1] for call in es.calls]
        self.assertLess(paths.index("/_license/start_trial?acknowledge=true"),
                        paths.index("/_security/user/kibana_system/_password"))
        self.assertEqual(paths.count("/_license/start_trial?acknowledge=true"), 1)
        self.assertEqual(paths.count("/_license"), 3)
        self.assertEqual(auth_result["license"], "trial")
        self.assertEqual(result["license"], "trial")
        self.assertEqual(result["license_expiry_date"], "2100-01-01T00:00:00Z")
        self.assertEqual(result["license_expiry_date_in_millis"], es.trial_expiry)

    def test_ineligible_trial_stops_configure_before_kibana_writes(self):
        es, kibana = FakeAPI(), FakeAPI()
        es.overrides[("GET", "/_license/trial_status")] = {"eligible_to_start_trial": False}
        with self.assertRaisesRegex(bootstrap.SetupError, "not eligible"):
            self.configure(es, kibana, license_mode="trial")
        self.assertTrue(all(call[0] == "GET" for call in es.calls + kibana.calls))
        self.assertEqual(kibana.calls, [])

    def test_disabled_prebuilt_install_has_no_rule_api_writes(self):
        kibana = FakeAPI()
        result = self.configure(kibana=kibana, prebuilt_rules=False)
        self.assertIsNone(result["prebuilt_rules"])
        self.assertFalse(any("/rules/" in call[1] for call in kibana.calls))

    def test_prebuilt_install_must_report_valid_counts(self):
        kibana = FakeAPI()
        kibana.overrides[("PUT", "/api/detection_engine/rules/prepackaged")] = {"rules_installed": 3}
        with self.assertRaisesRegex(bootstrap.SetupError, "installation counts"):
            self.configure(kibana=kibana)

    def test_failed_template_ack_stops_kibana_mutations(self):
        es, kibana = FakeAPI(), FakeAPI()
        es.overrides[("PUT", "/_index_template/logs-lab")] = {"acknowledged": False}
        with self.assertRaisesRegex(bootstrap.SetupError, "not acknowledged"):
            self.configure(es, kibana)
        self.assertTrue(all(call[0] == "GET" for call in kibana.calls))

    def test_catalog_revision_mismatch_has_no_remote_side_effects(self):
        self.catalog["revision"] = "b" * 40
        self.write_catalog()
        es, kibana = FakeAPI(), FakeAPI()
        with self.assertRaisesRegex(bootstrap.SetupError, "same upstream revision"):
            self.configure(es, kibana)
        self.assertEqual(es.calls + kibana.calls, [])

    def test_catalog_external_link_or_execution_flag_rejected(self):
        for field, value in [("url", "https://example.invalid/"), ("auto_execute", True)]:
            with self.subTest(field=field):
                entry = self.catalog["entries"][0]
                old, entry[field] = entry[field], value
                self.write_catalog()
                with self.assertRaisesRegex(bootstrap.SetupError, "invalid or executable"):
                    bootstrap.load_catalog(self.labs)
                entry[field] = old

    def test_catalog_uses_current_snapshot(self):
        generation = self.labs / ".releases/generation"
        generation.mkdir(parents=True)
        for name in ("manifest.json", "catalog.json"):
            (self.labs / name).rename(generation / name)
        (self.labs / "current").symlink_to(".releases/generation", target_is_directory=True)
        self.assertEqual(bootstrap.load_catalog(self.labs)[0]["revision"], self.revision)

    def test_catalog_reader_blocks_pointer_switch_and_cleanup_between_reads(self):
        old_generation = self.labs / ".releases/old"
        old_generation.mkdir(parents=True)
        for name in ("manifest.json", "catalog.json"):
            (self.labs / name).rename(old_generation / name)
        (self.labs / "current").symlink_to(".releases/old", target_is_directory=True)
        new_generation = self.labs / ".releases/new"
        new_generation.mkdir()
        new_manifest = {**self.manifest, "revision": "b" * 40}
        new_catalog = {**new_manifest, "entries": []}
        (new_generation / "manifest.json").write_text(json.dumps(new_manifest))
        (new_generation / "catalog.json").write_text(json.dumps(new_catalog))

        manifest_read, continue_read = threading.Event(), threading.Event()
        read_json = bootstrap.read_json

        def pause_between_reads(path):
            value = read_json(path)
            if path.name == "manifest.json":
                manifest_read.set()
                if not continue_read.wait(timeout=10):
                    raise AssertionError("Test did not release the catalog reader")
            return value

        writer = """
import fcntl, os, pathlib, shutil, sys
root = pathlib.Path(sys.argv[1])
with (root / '.sync.lock').open('rb') as lock:
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print('blocked')
    else:
        (root / 'next').symlink_to('.releases/new', target_is_directory=True)
        os.replace(root / 'next', root / 'current')
        shutil.rmtree(root / '.releases/old')
        print('updated')
"""
        with ThreadPoolExecutor(max_workers=1) as executor:
            with patch.object(bootstrap, "read_json", side_effect=pause_between_reads):
                reader = executor.submit(bootstrap.load_catalog, self.labs)
                try:
                    self.assertTrue(manifest_read.wait(timeout=5))
                    blocked_writer = subprocess.run([sys.executable, "-c", writer, str(self.labs)],
                                                    check=True, capture_output=True, text=True, timeout=5)
                    self.assertEqual(blocked_writer.stdout.strip(), "blocked")
                    self.assertTrue(old_generation.exists())
                finally:
                    continue_read.set()
                manifest, catalog = reader.result(timeout=5)
        self.assertEqual(manifest["revision"], self.revision)
        self.assertEqual(catalog["revision"], self.revision)
        successful_writer = subprocess.run([sys.executable, "-c", writer, str(self.labs)],
                                           check=True, capture_output=True, text=True, timeout=5)
        self.assertEqual(successful_writer.stdout.strip(), "updated")
        self.assertFalse(old_generation.exists())
        self.assertEqual(bootstrap.load_catalog(self.labs)[0]["revision"], "b" * 40)

    def test_catalog_markdown_is_escaped_and_labels_paid_prerequisites(self):
        self.catalog["entries"][0]["title"] = "[malicious](https://example.invalid)\n<script>"
        markdown = bootstrap.catalog_markdown(self.manifest, self.catalog)
        self.assertIn(r"\[malicious\]", markdown)
        self.assertNotIn("<script>", markdown)
        self.assertIn("유료 기능", markdown)
        self.assertIn(self.revision[:12], markdown)

    def test_existing_index_response_requires_name(self):
        kibana = FakeAPI()
        kibana.overrides[("GET", "/api/detection_engine/index")] = {}
        with self.assertRaisesRegex(bootstrap.SetupError, "no index name"):
            self.configure(kibana=kibana)

    def test_template_is_ordinary_ecs_index_with_high_priority(self):
        template = bootstrap.read_json(ROOT / "config/elasticsearch/logs-lab-template.json")
        self.assertNotIn("data_stream", template)
        self.assertGreater(template["priority"], 500)
        properties = template["template"]["mappings"]["properties"]
        self.assertEqual(properties["@timestamp"]["type"], "date")
        self.assertEqual(properties["event"]["properties"]["ingested"]["type"], "date")
        self.assertFalse(properties["event"]["properties"]["original"]["index"])
        self.assertEqual(properties["lab"]["properties"]["unmapped"]["type"], "flattened")
        self.assertEqual(properties["lab"]["properties"]["source_profile"]["type"], "keyword")
        self.assertEqual(properties["lab"]["properties"]["input_path"]["type"], "keyword")


class TrialLicenseTest(unittest.TestCase):
    def test_basic_mode_does_not_mutate_license(self):
        es = FakeAPI()
        self.assertEqual(bootstrap.ensure_license(es), {"license": "basic"})
        self.assertEqual([(call[0], call[1]) for call in es.calls], [("GET", "/_license")])

    def test_new_trial_checks_eligibility_then_starts_and_verifies_license(self):
        es = FakeAPI()
        result = bootstrap.ensure_license(es, "trial")
        self.assertEqual(result["license"], "trial")
        self.assertEqual([(call[0], call[1]) for call in es.calls], [
            ("GET", "/_license"), ("GET", "/_license/trial_status"),
            ("POST", "/_license/start_trial?acknowledge=true"), ("GET", "/_license")])

    def test_existing_active_trial_is_idempotent(self):
        es = FakeAPI(license_type="trial")
        first = bootstrap.ensure_license(es, "trial")
        second = bootstrap.ensure_license(es, "trial")
        self.assertEqual(first, second)
        self.assertEqual([call[1] for call in es.calls], ["/_license", "/_license"])

    def test_ineligible_trial_is_not_started_or_reset(self):
        es = FakeAPI()
        es.overrides[("GET", "/_license/trial_status")] = {"eligible_to_start_trial": False}
        with self.assertRaisesRegex(bootstrap.SetupError, "not eligible"):
            bootstrap.ensure_license(es, "trial")
        self.assertTrue(all(call[0] == "GET" for call in es.calls))

    def test_invalid_eligibility_is_not_treated_as_true(self):
        for value in (None, "true", 1):
            with self.subTest(value=value):
                es = FakeAPI()
                es.overrides[("GET", "/_license/trial_status")] = {"eligible_to_start_trial": value}
                with self.assertRaisesRegex(bootstrap.SetupError, "valid Trial eligibility"):
                    bootstrap.ensure_license(es, "trial")
                self.assertTrue(all(call[0] == "GET" for call in es.calls))

    def test_expired_trial_is_not_restarted(self):
        es = FakeAPI(license_type="trial")
        es.license_status = "expired"
        with self.assertRaisesRegex(bootstrap.SetupError, "expired or inactive"):
            bootstrap.ensure_license(es, "trial")
        self.assertEqual([call[1] for call in es.calls], ["/_license"])

    def test_missing_or_past_expiration_prevents_success(self):
        for value in (None, "4102444800000", True, 1):
            with self.subTest(value=value):
                es = FakeAPI(license_type="trial")
                es.trial_expiry = value
                with self.assertRaisesRegex(bootstrap.SetupError, "Trial expiration"):
                    bootstrap.ensure_license(es, "trial")

    def test_refused_activation_and_http_failure_are_not_basic_fallbacks(self):
        responses = [
            {"acknowledged": True, "trial_was_started": False},
            {"acknowledged": False, "trial_was_started": True},
            bootstrap.APIError("POST", "/_license/start_trial?acknowledge=true", 403),
        ]
        for response in responses:
            with self.subTest(response=response):
                es = FakeAPI()
                es.overrides[("POST", "/_license/start_trial?acknowledge=true")] = response
                with self.assertRaises(bootstrap.SetupError):
                    bootstrap.ensure_license(es, "trial")
                self.assertEqual(es.license_type, "basic")
                self.assertEqual(sum(call[0] != "GET" for call in es.calls), 1)

    def test_activation_acknowledgement_must_match_actual_license(self):
        es = FakeAPI()
        es.overrides[("POST", "/_license/start_trial?acknowledge=true")] = {
            "acknowledged": True, "trial_was_started": True}
        with self.assertRaisesRegex(bootstrap.SetupError, "could not be verified"):
            bootstrap.ensure_license(es, "trial")

    def test_basic_mode_refuses_trial_without_downgrade(self):
        es = FakeAPI(license_type="trial")
        with self.assertRaisesRegex(bootstrap.SetupError, "up --trial"):
            bootstrap.ensure_license(es, "basic")
        self.assertEqual([(call[0], call[1]) for call in es.calls], [("GET", "/_license")])

    def test_paid_license_and_unknown_mode_are_never_replaced(self):
        es = FakeAPI(license_type="platinum")
        with self.assertRaisesRegex(bootstrap.SetupError, "Existing license is unchanged"):
            bootstrap.ensure_license(es, "trial")
        self.assertTrue(all(call[0] == "GET" for call in es.calls))
        es.calls.clear()
        with self.assertRaisesRegex(bootstrap.SetupError, "basic or trial"):
            bootstrap.ensure_license(es, "unlimited")
        self.assertEqual(es.calls, [])


class HTTPTest(unittest.TestCase):
    def api(self):
        return bootstrap.API("http://localhost:5601", "DO-NOT-PRINT-ME")

    def test_error_does_not_echo_password_or_response_body(self):
        body = io.BytesIO(b"DO-NOT-PRINT-ME")
        error = urllib.error.HTTPError("http://localhost", 401, "unauthorized", {}, body)
        with patch.object(bootstrap.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(bootstrap.APIError) as raised:
                self.api().request("GET", "/api/status")
        self.assertNotIn("DO-NOT-PRINT-ME", str(raised.exception))
        self.assertEqual(raised.exception.status, 401)
        self.assertTrue(body.closed)

    def test_only_requested_not_found_is_allowed(self):
        body = io.BytesIO(b"{}")
        error = urllib.error.HTTPError("http://localhost", 404, "missing", {}, body)
        with patch.object(bootstrap.urllib.request, "urlopen", side_effect=error):
            result = self.api().request("GET", "/api/detection_engine/index", allow_status=(404,))
            self.assertEqual(result, {"_http_status": 404})
            self.assertTrue(body.closed)
            with self.assertRaises(bootstrap.APIError):
                self.api().request("GET", "/api/status")

    def test_api_error_in_success_response_is_not_silent(self):
        response = Mock()
        response.read.return_value = b'{"success": false, "errors": ["broken"]}'
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        with patch.object(bootstrap.urllib.request, "urlopen", return_value=context):
            with self.assertRaisesRegex(bootstrap.SetupError, "API error"):
                self.api().request("POST", "/api/saved_objects/dashboard/test")

    def test_readiness_retries_transient_errors_but_not_auth_failure(self):
        api = Mock()
        api.request.side_effect = [bootstrap.APIError("GET", "/api/status", 503), {"ready": True}]
        with patch.object(bootstrap.time, "sleep"):
            self.assertEqual(bootstrap.wait_ready(api, "/api/status", attempts=2), {"ready": True})
        api.request.reset_mock(side_effect=True)
        api.request.side_effect = bootstrap.APIError("GET", "/api/status", 401)
        with self.assertRaises(bootstrap.APIError):
            bootstrap.wait_ready(api, "/api/status", attempts=10)
        self.assertEqual(api.request.call_count, 1)

    def test_readiness_deadline_fails(self):
        api = Mock()
        api.request.return_value = {"status": "red"}
        with patch.object(bootstrap.time, "sleep"):
            with self.assertRaisesRegex(bootstrap.SetupError, "deadline"):
                bootstrap.wait_ready(api, "/health", attempts=2, predicate=lambda value: value["status"] == "green")
        self.assertEqual(api.request.call_count, 2)

    def test_detection_version_header_only_on_detection_routes(self):
        response = Mock()
        response.read.return_value = b'{}'
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        with patch.object(bootstrap.urllib.request, "urlopen", return_value=context) as mocked:
            self.api().request("POST", "/api/detection_engine/index")
            self.assertEqual(mocked.call_args.args[0].get_header("Elastic-api-version"), "2023-10-31")
            self.api().request("GET", "/api/status")
            self.assertIsNone(mocked.call_args.args[0].get_header("Elastic-api-version"))


if __name__ == "__main__":
    unittest.main()
