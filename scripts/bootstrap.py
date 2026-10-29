#!/usr/bin/env python3
"""Idempotent, explicit setup of this Compose lab; uses only Python's standard library.

Trial activation requires explicit LICENSE_MODE=trial. The process never executes
upstream examples, loads log fixtures, or enables detection rules. Managed
templates/data view/catalog are reconciled on each configure invocation.
Existing user-enabled prebuilt rules stay enabled.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

try:
    from scripts.source_profiles import index_patterns, load_profiles
    from scripts.cases import case_index_patterns, load_cases
except ModuleNotFoundError as error:
    if error.name not in ("scripts", "scripts.source_profiles", "scripts.cases"):
        raise
    # Direct execution in the helper container puts /scripts on sys.path.
    from source_profiles import index_patterns, load_profiles
    from cases import case_index_patterns, load_cases


DEFAULT_PROFILES = Path(__file__).resolve().parents[1] / "config/source-profiles.json"
DEFAULT_CASES = Path(__file__).resolve().parents[1] / ".cases/registry.json"


class SetupError(RuntimeError):
    pass


class APIError(SetupError):
    def __init__(self, method: str, path: str, status: int):
        self.status = status
        # Do not print response bodies: authentication endpoints may echo data.
        super().__init__(f"{method} {path} failed with HTTP {status}")


class API:
    def __init__(self, base_url: str, password: str, ca_cert: str | None = None,
                 timeout: int = 120):
        if not base_url.startswith(("https://", "http://")):
            raise SetupError("API URL must use http:// or https://")
        self.base_url = base_url.rstrip("/")
        self.auth = base64.b64encode(f"elastic:{password}".encode()).decode()
        self.context = ssl.create_default_context(cafile=ca_cert)
        self.timeout = timeout

    def request(self, method: str, path: str, payload: dict | None = None,
                allow_status: tuple[int, ...] = (), timeout: float | None = None) -> dict:
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Authorization": f"Basic {self.auth}", "kbn-xsrf": "lab-bootstrap",
                     "Content-Type": "application/json", "Accept": "application/json"},
        )
        if path.startswith("/api/detection_engine/"):
            request.add_header("elastic-api-version", "2023-10-31")
        try:
            with urllib.request.urlopen(request, context=self.context,
                                        timeout=self.timeout if timeout is None else timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            if status in allow_status:
                return {"_http_status": status}
            raise APIError(method, path, status) from None
        except urllib.error.URLError as error:
            # Certificate failures are fatal, rather than a readiness retry.
            if isinstance(error.reason, ssl.SSLError):
                raise SetupError(f"TLS verification failed for {self.base_url}") from None
            raise ConnectionError(f"Cannot reach {self.base_url}") from None
        try:
            result = json.loads(raw) if raw else {}
        except (ValueError, UnicodeError):
            raise SetupError(f"{method} {path} returned invalid JSON") from None
        if not isinstance(result, dict):
            raise SetupError(f"{method} {path} returned an unexpected response")
        if result.get("error") or result.get("errors") or result.get("success") is False:
            raise SetupError(f"{method} {path} returned an API error")
        return result


def wait_ready(api: API, path: str, *, attempts: int = 120, interval: float = 2,
               deadline_seconds: float = 300, predicate=None) -> dict:
    """Retry readiness only, never retry a configuration/authentication failure."""
    deadline = time.monotonic() + deadline_seconds
    for attempt in range(attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            result = api.request("GET", path, timeout=min(5, remaining))
            if predicate is None or predicate(result):
                return result
        except APIError as error:
            if error.status not in (429, 502, 503, 504):
                raise
        except (ConnectionError, TimeoutError):
            pass
        if attempt + 1 < attempts:
            time.sleep(max(0, min(interval, deadline - time.monotonic())))
    raise SetupError(f"Readiness deadline exceeded for {path}")


def require_ack(result: dict, action: str) -> None:
    if result.get("acknowledged") is not True:
        raise SetupError(f"{action} was not acknowledged")


def ensure_license(es: API, license_mode: str = "basic") -> dict:
    """Reconcile only an explicitly requested, eligible Trial activation.

    No license is downgraded, reset, renewed, or replaced with a paid license.
    Elasticsearch remains the authority for trial eligibility and expiration.
    """
    if license_mode not in ("basic", "trial"):
        raise SetupError("LICENSE_MODE must be basic or trial")
    license_info = es.request("GET", "/_license").get("license", {})
    if not isinstance(license_info, dict):
        raise SetupError("Elasticsearch returned invalid license information")
    license_type, status = license_info.get("type"), license_info.get("status")
    if license_mode == "basic":
        if license_type != "basic" or status != "active":
            raise SetupError("Expected an active Basic license. Existing license is unchanged. "
                             "For an active Trial, use builder.py up --trial or LICENSE_MODE=trial.")
        return {"license": "basic"}

    if license_type == "trial":
        if status != "active":
            raise SetupError("The existing Trial is expired or inactive; it will not be restarted. "
                             "Use Elastic license management or request a trial extension.")
    elif license_type == "basic" and status == "active":
        eligibility = es.request("GET", "/_license/trial_status").get("eligible_to_start_trial")
        if eligibility is not True:
            if eligibility is False:
                raise SetupError("This cluster is not eligible to start a Trial for this major version. "
                                 "No license was changed; request an extension at https://www.elastic.co/trialextension.")
            raise SetupError("Elasticsearch did not return a valid Trial eligibility result")
        started = es.request("POST", "/_license/start_trial?acknowledge=true")
        if started.get("acknowledged") is not True or started.get("trial_was_started") is not True:
            raise SetupError("Elasticsearch did not confirm Trial activation; no Basic fallback was selected.")
        license_info = es.request("GET", "/_license").get("license", {})
    else:
        raise SetupError("Trial mode requires an active Basic or Trial license. Existing license is unchanged.")

    if (not isinstance(license_info, dict) or license_info.get("type") != "trial"
            or license_info.get("status") != "active"):
        raise SetupError("Trial activation could not be verified; expected an active Trial license.")
    expires = license_info.get("expiry_date_in_millis")
    if type(expires) is not int or expires <= int(time.time() * 1000):
        raise SetupError("Trial expiration is missing, invalid, or already passed.")
    try:
        expires_utc = datetime.fromtimestamp(expires / 1000, timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        raise SetupError("Trial expiration is outside the supported date range") from None
    return {"license": "trial", "license_expiry_date_in_millis": expires,
            "license_expiry_date": expires_utc}


def profile_patterns(profiles_path: Path) -> list[str]:
    try:
        return index_patterns(load_profiles(profiles_path))
    except (ValueError, OSError) as error:
        raise SetupError(f"Invalid source profiles: {error}") from None


def source_configuration(profiles_path: Path, cases_path: Path) -> tuple[dict, list[str]]:
    try:
        profiles = load_profiles(profiles_path)
    except (ValueError, OSError) as error:
        raise SetupError(f"Invalid source profiles: {error}") from None
    try:
        cases = load_cases(cases_path, profiles)
    except (ValueError, OSError) as error:
        raise SetupError(f"Invalid case registry: {error}") from None
    return profiles, cases


def auth_setup(es: API, kibana_password: str, logstash_password: str,
               *, license_mode: str = "basic", profiles_path: Path = DEFAULT_PROFILES,
               cases_path: Path = DEFAULT_CASES) -> dict:
    profiles, _ = source_configuration(profiles_path, cases_path)
    patterns = index_patterns(profiles)
    wait_ready(es, "/_cluster/health?wait_for_status=yellow&timeout=5s",
               predicate=lambda value: value.get("status") in ("yellow", "green") and not value.get("timed_out"))
    license_info = ensure_license(es, license_mode)
    es.request("POST", "/_security/user/kibana_system/_password", {"password": kibana_password})
    es.request("PUT", "/_security/role/lab_logstash_writer", {
        "cluster": ["monitor"],
        "indices": [{"names": patterns,
                     "privileges": ["write", "create_doc", "create_index", "auto_configure", "view_index_metadata"]}],
    })
    es.request("PUT", "/_security/user/logstash_internal", {
        "password": logstash_password, "roles": ["lab_logstash_writer"],
        "full_name": "Compose lab Logstash writer", "enabled": True,
    })
    return license_info


def read_json(path: Path) -> dict:
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SetupError(f"Cannot read valid JSON from {path}: {error}") from None
    if not isinstance(result, dict):
        raise SetupError(f"Expected a JSON object at {path}")
    return result


def load_catalog(labs_dir: Path) -> tuple[dict, dict]:
    """Keep the current generation alive through both reads and validation.

    The synchronizer holds this same lock exclusively while switching current
    and pruning old releases. Open read-only because /labs is a read-only mount.
    Closing the handle also releases the lock on validation/error paths.
    """
    with (labs_dir / ".sync.lock").open("rb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
        return _load_catalog_locked(labs_dir)


def _load_catalog_locked(labs_dir: Path) -> tuple[dict, dict]:
    snapshot = (labs_dir / "current").resolve() if (labs_dir / "current").exists() else labs_dir
    manifest, catalog = read_json(snapshot / "manifest.json"), read_json(snapshot / "catalog.json")
    revision = manifest.get("revision", "")
    repository = "https://github.com/elastic/elastic-labs"
    if (not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision)
            or manifest.get("repository") != repository
            or catalog.get("revision") != revision
            or catalog.get("repository") != repository
            or not isinstance(catalog.get("entries"), list)):
        raise SetupError("Labs catalog and manifest must identify the same upstream revision")
    prefix = f"{repository}/blob/{revision}/"
    for entry in catalog["entries"]:
        if (not isinstance(entry, dict) or not isinstance(entry.get("title"), str)
                or not isinstance(entry.get("path"), str)
                or not isinstance(entry.get("url"), str)
                or not entry["url"].startswith(prefix)
                or any(char in entry["url"] for char in "\r\n<>()")
                or entry.get("auto_execute") is not False):
            raise SetupError("Labs catalog contains an invalid or executable entry")
    return manifest, catalog


def markdown_escape(text: str) -> str:
    return re.sub(r"([\\`*_{}\[\]<>()#!|])", r"\\\1", text.replace("\n", " ").replace("\r", " "))


def catalog_markdown(manifest: dict, catalog: dict) -> str:
    revision = manifest["revision"]
    rows = ["# Elastic Labs catalog", "",
            f"Upstream revision: [`{revision[:12]}`](https://github.com/elastic/elastic-labs/tree/{revision})", "",
            "이 카탈로그는 시작 시 동기화한 공식 elastic-labs 예제를 반영합니다.",
            "예제 코드는 자동 실행하지 않습니다. 각 예제의 사전 조건을 확인하세요.",
            "일부 AI, ML, 클라우드 예제에는 유료 기능 또는 별도 서비스가 필요합니다.", "",
            "case 준비: `python3 builder.py case init --name incident001`.",
            "실제 로그: `logs/<case>/<source>/` → Logstash → source+case 인덱스. 기존 `logs/<source>/`도 지원합니다.",
            "호스트에서 `python3 builder.py sources`로 폴더와 대상 인덱스를 확인하세요.",
            "Discover의 Lab logs는 원본 이벤트 시간, Lab logs — ingest time은 수집 시간으로 조회합니다.",
            "등록된 case에는 `Case <case>`와 `Case <case> — ingest time` 데이터 뷰를 구성합니다.",
            "case 데이터 뷰 선택은 예약 실행 룰의 검색 범위를 변경하지 않습니다. 테스트 룰도 case로 제한하세요.",
            "데이터 소스 폴더는 인덱스만 선택합니다. 탐지 규칙의 필드·쿼리·시간 조건도 충족해야 합니다.", ""]
    for category, label in [("security", "Security"), ("observability", "Observability"),
                            ("search-and-ai", "Search and AI")]:
        entries = [entry for entry in catalog["entries"] if entry.get("category") == category]
        rows.extend([f"## {label} ({len(entries)})", ""])
        if not entries:
            rows.append("이 revision의 카탈로그에는 해당 범주 예제가 없습니다.")
        for entry in entries[:25]:
            display_path = entry["path"].replace("`", "").replace("\r", " ").replace("\n", " ")
            rows.append(f"- [{markdown_escape(entry['title'])}]({entry['url']}) — `{display_path}`")
        if len(entries) > 25:
            rows.append("전체 목록은 호스트의 `.cache/elastic-labs/catalog.json`에서 확인할 수 있습니다.")
        rows.append("")
    return "\n".join(rows)


def install_catalog(kibana: API, manifest: dict, catalog: dict) -> None:
    """Legacy public Saved Objects API is supported on the pinned 9.x release.

    Avoid 9.6-only experimental markdown APIs. These two IDs are IaC-managed;
    overwrite refreshes the catalog without creating duplicates on restart.
    """
    vis_id, dashboard_id = "elastic-labs-catalog-markdown", "elastic-labs-catalog"
    kibana.request("POST", f"/api/saved_objects/visualization/{vis_id}?overwrite=true", {
        "attributes": {
            "title": "Elastic Labs — synchronized examples",
            "description": f"Managed by Compose bootstrap at upstream {manifest['revision']}",
            "visState": json.dumps({"title": "Elastic Labs catalog", "type": "markdown", "aggs": [],
                                    "params": {"markdown": catalog_markdown(manifest, catalog), "openLinksInNewTab": True}}),
            "uiStateJSON": "{}", "kibanaSavedObjectMeta": {"searchSourceJSON": "{}"},
        },
        "references": [],
    })
    kibana.request("POST", f"/api/saved_objects/dashboard/{dashboard_id}?overwrite=true", {
        "attributes": {
            "title": "Elastic Labs — latest examples", "description": "IaC-managed upstream example catalog",
            "panelsJSON": json.dumps([{"type": "visualization", "panelIndex": "1", "panelRefName": "panel_1",
                                      "gridData": {"x": 0, "y": 0, "w": 48, "h": 36, "i": "1"},
                                      "embeddableConfig": {}}]),
            "optionsJSON": '{"useMargins":true,"hidePanelTitles":false}',
            "timeRestore": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": '{"query":{"query":"","language":"kuery"},"filter":[]}'},
        },
        "references": [{"name": "panel_1", "type": "visualization", "id": vis_id}],
    })


def upsert_data_view(kibana: API, view_id: str, name: str, time_field: str,
                     patterns: list[str]) -> None:
    view = kibana.request("POST", "/api/data_views/data_view", {
        "data_view": {"id": view_id, "title": ",".join(patterns), "name": name,
                      "timeFieldName": time_field, "allowNoIndex": True},
        "override": True,
    })
    if view.get("data_view", {}).get("id") != view_id:
        raise SetupError(f"Kibana did not return the expected data view ID: {view_id}")


def configure(es: API, kibana: API, config_dir: Path, labs_dir: Path,
              *, prebuilt_rules: bool = True, license_mode: str = "basic",
              profiles_path: Path = DEFAULT_PROFILES,
              cases_path: Path = DEFAULT_CASES) -> dict:
    if license_mode not in ("basic", "trial"):
        raise SetupError("LICENSE_MODE must be basic or trial")
    # Validate local inputs before any remote configuration mutation.
    profiles, cases = source_configuration(profiles_path, cases_path)
    patterns = index_patterns(profiles)
    manifest, catalog = load_catalog(labs_dir)
    pipeline = read_json(config_dir / "lab-ingest.json")
    template = read_json(config_dir / "logs-lab-template.json")
    template["index_patterns"] = patterns
    wait_ready(es, "/_cluster/health?wait_for_status=yellow&timeout=5s",
               predicate=lambda value: value.get("status") in ("yellow", "green") and not value.get("timed_out"))
    license_info = ensure_license(es, license_mode)
    wait_ready(kibana, "/api/status",
               predicate=lambda value: value.get("status", {}).get("overall", {}).get("level") == "available")
    require_ack(es.request("PUT", "/_ingest/pipeline/lab-ingest", pipeline), "Ingest pipeline")
    require_ack(es.request("PUT", "/_index_template/logs-lab", template), "Index template")
    for view_id, name, time_field in (
        ("lab-logs", "Lab logs", "@timestamp"),
        ("lab-logs-ingested", "Lab logs — ingest time", "event.ingested"),
    ):
        upsert_data_view(kibana, view_id, name, time_field, patterns)
    case_views = {}
    for case_name in cases:
        case_patterns = case_index_patterns(profiles, case_name)
        view_id = f"lab-case-{case_name}"
        upsert_data_view(kibana, view_id, f"Case {case_name}", "@timestamp", case_patterns)
        upsert_data_view(kibana, f"{view_id}-ingested", f"Case {case_name} — ingest time",
                         "event.ingested", case_patterns)
        case_views[case_name] = {"data_view": view_id, "ingest_data_view": f"{view_id}-ingested"}
    view_id = "lab-logs"
    require_ack(kibana.request("POST", "/api/data_views/default", {"data_view_id": view_id, "force": True}),
                "Default data view")
    index = kibana.request("GET", "/api/detection_engine/index", allow_status=(404,))
    if index.get("_http_status") == 404:
        require_ack(kibana.request("POST", "/api/detection_engine/index"), "Detection engine index")
    elif not isinstance(index.get("name"), str) or not index["name"]:
        raise SetupError("Detection index API returned no index name")
    rules = None
    if prebuilt_rules:
        rules = kibana.request("PUT", "/api/detection_engine/rules/prepackaged")
        fields = ("rules_installed", "rules_updated", "timelines_installed", "timelines_updated")
        if any(type(rules.get(field)) is not int or rules[field] < 0 for field in fields):
            raise SetupError("Prebuilt-rule API did not confirm installation counts")
        rules = {field: rules[field] for field in fields}
    install_catalog(kibana, manifest, catalog)
    return {**license_info, "data_view": view_id, "ingest_data_view": "lab-logs-ingested",
            "case_views": case_views,
            "labs_revision": manifest["revision"],
            "labs_examples": len(catalog["entries"]), "prebuilt_rules": rules,
            "dashboard": "/app/dashboards#/view/elastic-labs-catalog"}


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SetupError(f"{name} must be set")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("auth", "configure"))
    parser.add_argument("--config-dir", type=Path, default=Path("/config/elasticsearch"))
    parser.add_argument("--labs-dir", type=Path, default=Path("/labs"))
    parser.add_argument("--profiles", type=Path, default=Path("/config/source-profiles.json"))
    parser.add_argument("--cases", type=Path, default=Path("/cases/registry.json"))
    args = parser.parse_args()
    try:
        es_url = os.environ.get("ES_URL", "https://elasticsearch:9200")
        if not es_url.startswith("https://"):
            raise SetupError("ES_URL must use verified HTTPS")
        password = required_env("ELASTIC_PASSWORD")
        license_mode = os.environ.get("LICENSE_MODE", "basic").lower()
        if license_mode not in ("basic", "trial"):
            raise SetupError("LICENSE_MODE must be basic or trial")
        es = API(es_url, password, os.environ.get("CA_CERT", "/certs/ca/ca.crt"), timeout=120)
        if args.phase == "auth":
            license_info = auth_setup(es, required_env("KIBANA_PASSWORD"), required_env("LOGSTASH_PASSWORD"),
                                      license_mode=license_mode, profiles_path=args.profiles,
                                      cases_path=args.cases)
            print(json.dumps({"service_credentials": "configured", **license_info}, ensure_ascii=False))
        else:
            prebuilt = os.environ.get("PREBUILT_RULES", "true").lower()
            if prebuilt not in ("true", "false"):
                raise SetupError("PREBUILT_RULES must be true or false")
            kibana = API(os.environ.get("KIBANA_URL", "http://kibana:5601"), password, timeout=300)
            print(json.dumps(configure(es, kibana, args.config_dir, args.labs_dir,
                                       prebuilt_rules=prebuilt == "true", license_mode=license_mode,
                                       profiles_path=args.profiles, cases_path=args.cases), ensure_ascii=False))
    except (SetupError, OSError, ConnectionError, TimeoutError) as error:
        print(f"Bootstrap failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
