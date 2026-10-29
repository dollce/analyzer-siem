#!/usr/bin/env python3
"""Inform about published Elastic releases without changing the configured stack.

The official Elasticsearch GitHub release marked `latest` is the reference.
The artifacts API is deliberately not used: it also lists unreleased builds.
This is a release notice, not proof that every desired image or upgrade path is
compatible. Network and cache failures must never prevent lifecycle commands.
"""

import datetime as dt
import json
import math
import os
from pathlib import Path
import queue
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

SOURCE_URL = "https://api.github.com/repos/elastic/elasticsearch/releases/latest"
RELEASE_URL = "https://github.com/elastic/elasticsearch/releases/tag/v"
TIMEOUT_SECONDS = 3.0
CACHE_TTL_SECONDS = 24 * 60 * 60
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_CACHE_BYTES = 4096
VERSION_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


class VersionCheckError(RuntimeError):
    """An informational release lookup failed."""


def version_tuple(value):
    if not isinstance(value, str) or not VERSION_PATTERN.fullmatch(value):
        raise ValueError("Expected a stable X.Y.Z release version")
    return tuple(int(part) for part in value.split("."))


def parse_release(payload):
    """Accept only a publicly published, non-prerelease stable release."""
    if not isinstance(payload, dict):
        raise VersionCheckError("Unexpected release response")
    if payload.get("draft") is not False or payload.get("prerelease") is not False:
        raise VersionCheckError("Upstream response is not a stable published release")
    tag = payload.get("tag_name", "")
    if not isinstance(tag, str) or not tag.startswith("v"):
        raise VersionCheckError("Unexpected upstream release tag")
    version = tag[1:]
    try:
        version_tuple(version)
    except ValueError as error:
        raise VersionCheckError("Upstream tag is not a stable version") from error
    if payload.get("html_url") != RELEASE_URL + version:
        raise VersionCheckError("Unexpected upstream release link")
    published = payload.get("published_at")
    if not isinstance(published, str):
        raise VersionCheckError("Release has no publication timestamp")
    try:
        parsed = dt.datetime.fromisoformat(published.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Missing timezone")
    except ValueError as error:
        raise VersionCheckError("Invalid release publication timestamp") from error
    return {"version": version, "url": RELEASE_URL + version, "published_at": published}


def fetch_release():
    request = urllib.request.Request(SOURCE_URL, headers={
        "User-Agent": "analyzer-siem-version-check/1",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        error.close()
        raise VersionCheckError("Release service is unavailable") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise VersionCheckError("Release response exceeds size limit")
    try:
        return parse_release(json.loads(raw))
    except (ValueError, UnicodeError) as error:
        raise VersionCheckError("Release service returned invalid JSON") from error


def bounded_fetch():
    """Bound the caller's wall time, including DNS and slow response bodies.

    urllib's socket timeout is per operation. A daemon worker plus a queue wait
    keeps the whole informational lookup bounded; only this caller writes cache,
    so an expired request can never modify state later in the background.
    """
    result = queue.Queue(maxsize=1)

    def worker():
        try:
            result.put((True, fetch_release()))
        except Exception as error:
            result.put((False, error))

    threading.Thread(target=worker, name="elastic-release-check", daemon=True).start()
    try:
        success, value = result.get(timeout=TIMEOUT_SECONDS)
    except queue.Empty:
        raise VersionCheckError("Release lookup timed out") from None
    if not success:
        raise VersionCheckError("Release lookup failed") from value
    return value


def read_cache(cache_dir, now):
    try:
        path = Path(cache_dir) / "latest.json"
        with path.open("rb") as source:
            raw = source.read(MAX_CACHE_BYTES + 1)
        if len(raw) > MAX_CACHE_BYTES:
            return None
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("source") != SOURCE_URL:
            return None
        checked = payload.get("checked_at")
        if type(checked) not in (int, float) or not math.isfinite(checked) or checked < 0 or checked > now:
            return None
        release = parse_release({
            "draft": False, "prerelease": False,
            "tag_name": "v" + payload["version"],
            "html_url": payload["url"], "published_at": payload["published_at"],
        })
        return {**release, "checked_at": checked}
    except (OSError, ValueError, TypeError, KeyError, VersionCheckError):
        return None


def write_cache(cache_dir, release, now):
    directory = Path(cache_dir)
    directory.mkdir(parents=True, exist_ok=True)
    payload = {**release, "source": SOURCE_URL, "checked_at": now}
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=directory, prefix=".latest-", delete=False) as target:
            temporary = Path(target.name)
            json.dump(payload, target, sort_keys=True)
            target.write("\n")
        os.replace(temporary, directory / "latest.json")
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def report_latest(current_version, *, cache_dir, offline=False, force=False, stream=None):
    """Print one informational notice and return status; never update the stack.

    Status values are fresh, cached, offline-cache, stale-cache, unavailable,
    or offline. `newer` compares numeric version tuples; stale/offline values
    explicitly describe historical knowledge instead of claiming a live check.
    force=True bypasses only the 24-hour successful-result cache, not offline.
    """
    stream = sys.stdout if stream is None else stream
    try:
        current = version_tuple(current_version)
    except ValueError:
        print("Version check unavailable: configured version is not stable X.Y.Z. No automatic upgrade.", file=stream)
        return {"status": "unavailable", "newer": False, "latest": None}
    now = time.time()
    cached = read_cache(cache_dir, now)
    release = None
    status = "unavailable"
    if offline:
        release, status = cached, "offline-cache" if cached else "offline"
    elif cached and now - cached["checked_at"] < CACHE_TTL_SECONDS and not force:
        release, status = cached, "cached"
    else:
        try:
            release = bounded_fetch()
            status = "fresh"
            try:
                write_cache(cache_dir, release, now)
            except OSError:
                # A read-only/full cache must not turn a good lookup into failure.
                pass
        except (VersionCheckError, OSError, ValueError, TypeError, KeyError):
            release, status = cached, "stale-cache" if cached else "unavailable"
    if not release:
        reason = "offline; no valid cache" if offline else "lookup failed or timed out"
        print(f"Version check skipped ({reason}). Stack remains pinned to {current_version}; no automatic upgrade.", file=stream)
        return {"status": status, "newer": False, "latest": None}
    latest = release["version"]
    newer = version_tuple(latest) > current
    source = {"fresh": "live published release", "cached": "successful lookup cached for up to 24h",
              "offline-cache": "offline cached release; latest status unverified",
              "stale-cache": "lookup failed; last successful cached release, latest status unverified"}[status]
    if newer:
        print(f"NOTICE: Elastic {latest} is available (configured {current_version}; {source}). "
              f"No automatic upgrade. Review compatibility and update all Stack components together: {release['url']}", file=stream)
    else:
        print(f"Elastic Stack pinned to {current_version}; published release {latest} ({source}). No automatic upgrade.", file=stream)
    return {"status": status, "newer": newer, "latest": latest, "url": release["url"]}
