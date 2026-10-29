#!/usr/bin/env python3
"""Refresh the official Elastic Labs source and a non-executable example catalog.

Only Python's standard library is required. A successful refresh switches the
source, manifest, and catalog together through one atomic symlink replacement.
No upstream code, installers, notebooks, or sample ingest commands are executed.
"""

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
import uuid


REPOSITORY = "https://github.com/elastic/elastic-labs"
API = "https://api.github.com/repos/elastic/elastic-labs"
DEFAULT_ROOT = Path(__file__).resolve().parents[1] / ".cache" / "elastic-labs"
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 20000
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")


class SyncError(RuntimeError):
    """A refresh failed without selecting incomplete content."""


def request(url):
    return urlopen(Request(url, headers={
        "User-Agent": "elastic-siem-lab-sync/1",
        "Accept": "application/vnd.github+json",
    }), timeout=60)


def resolve_revision(ref):
    """Resolve a branch/tag each run; full commit pins need no API lookup."""
    if SHA_PATTERN.fullmatch(ref):
        return ref
    if not ref or len(ref) > 256 or any(ord(c) < 32 for c in ref):
        raise SyncError("Invalid upstream ref")
    with request(f"{API}/commits/{quote(ref, safe='')}") as response:
        payload = response.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise SyncError("GitHub commit metadata exceeds 1 MiB")
    revision = json.loads(payload)["sha"]
    if not isinstance(revision, str) or not SHA_PATTERN.fullmatch(revision):
        raise SyncError("GitHub did not return a full commit SHA")
    return revision


def download_archive(revision, target):
    digest = hashlib.sha256()
    count = 0
    url = f"https://codeload.github.com/elastic/elastic-labs/tar.gz/{revision}"
    with request(url) as response, target.open("xb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            count += len(chunk)
            if count > MAX_ARCHIVE_BYTES:
                raise SyncError("Upstream compressed archive exceeds 512 MiB")
            digest.update(chunk)
            output.write(chunk)
    return digest.hexdigest()


def extract_archive(archive, source, revision):
    """Extract regular files/directories only, with bounded sizes and safe paths."""
    source.mkdir()
    expected_prefix = f"elastic-labs-{revision}"
    count = total = 0
    seen = set()
    with tarfile.open(archive, mode="r|gz") as bundle:
        for member in bundle:
            count += 1
            if count > MAX_ENTRIES:
                raise SyncError("Upstream archive contains too many entries")
            raw = member.name.rstrip("/")
            parts = raw.split("/")
            if (not raw or raw.startswith("/") or "\\" in raw or "\x00" in raw
                    or any(part in ("", ".", "..") for part in parts)
                    or parts[0] != expected_prefix):
                raise SyncError(f"Unsafe archive path: {member.name!r}")
            if not (member.isdir() or member.isfile()) or member.issparse():
                raise SyncError(f"Unsupported archive entry: {member.name!r}")
            relative = PurePosixPath(*parts[1:])
            if str(relative) == ".":
                if not member.isdir():
                    raise SyncError("Archive root is not a directory")
                continue
            if str(relative) in seen:
                raise SyncError(f"Duplicate archive path: {relative}")
            seen.add(str(relative))
            destination = source.joinpath(*relative.parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            total += member.size
            if member.size < 0 or member.size > MAX_FILE_BYTES or total > MAX_EXTRACTED_BYTES:
                raise SyncError("Upstream archive exceeds extraction size limits")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with contextlib.closing(bundle.extractfile(member)) as incoming:
                if incoming is None:
                    raise SyncError(f"Unable to read archive entry: {relative}")
                with destination.open("xb") as output:
                    shutil.copyfileobj(incoming, output, length=1024 * 1024)
            # Preserve no upstream executable, ownership, or special permission bits.
            destination.chmod(0o644)
    if not (source / "README.md").is_file():
        raise SyncError("Archive has no repository README.md")
    return count, total


def create_catalog(source, revision, timestamp):
    entries = []
    accepted_roots = {"notebooks", "example-apps", "supporting-blog-content", "supporting-video-content"}
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        if relative.parts[0] not in accepted_roots or any(p.startswith(".") for p in relative.parts):
            continue
        is_notebook = path.suffix == ".ipynb" and not path.name.startswith("_nbtest")
        is_guide = (path.name.lower() == "readme.md" or
                    ("security-labs" in relative.parts and path.suffix.lower() == ".md"))
        if not (is_notebook or is_guide):
            continue
        category = ("security" if "security-labs" in relative.parts else
                    "observability" if "observability-labs" in relative.parts else "search-and-ai")
        title = relative.parent.name if path.name.lower() == "readme.md" else path.stem
        relative_path = relative.as_posix()
        entries.append({
            "id": hashlib.sha256(relative_path.encode()).hexdigest()[:16],
            "title": title.replace("-", " ").replace("_", " "),
            "category": category,
            "kind": "notebook" if is_notebook else "guide",
            "path": relative_path,
            "url": f"{REPOSITORY}/blob/{revision}/{quote(relative_path, safe='/')}",
            "auto_execute": False,
            "compatibility": "not-validated",
        })
    entries.sort(key=lambda entry: (entry["category"] != "security", entry["category"], entry["path"]))
    return {"schema_version": 1, "repository": REPOSITORY, "revision": revision,
            "generated_at": timestamp, "entries": entries}


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def validate_layout(root):
    """Never overwrite an unrecognized user directory or symlink."""
    if root.is_symlink():
        raise SyncError("Cache root must not be a symlink")
    root.mkdir(parents=True, exist_ok=True)
    releases = root / ".releases"
    if releases.is_symlink():
        raise SyncError("Cache .releases must not be a symlink")
    releases.mkdir(exist_ok=True)
    for name in ("source", "manifest.json", "catalog.json"):
        path = root / name
        if os.path.lexists(path) and (not path.is_symlink() or os.readlink(path) != f"current/{name}"):
            raise SyncError(f"Refusing to overwrite unmanaged cache path: {path}")
    current = root / "current"
    if os.path.lexists(current):
        if not current.is_symlink():
            raise SyncError("Cache current must be a managed symlink")
        target = PurePosixPath(os.readlink(current))
        if len(target.parts) != 2 or target.parts[0] != ".releases" or target.parts[1].startswith("."):
            raise SyncError("Cache current points outside managed releases")
        if (root / target).is_symlink():
            raise SyncError("Cache release directory must not be a symlink")


@contextlib.contextmanager
def cache_lock(root):
    fd = os.open(root / ".sync.lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SyncError("Another Elastic Labs synchronization is running") from error
        yield
    finally:
        os.close(fd)


def cached_manifest(root, ref):
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        catalog = json.loads((root / "catalog.json").read_text(encoding="utf-8"))
        revision = manifest["revision"]
        if (not SHA_PATTERN.fullmatch(revision) or catalog["revision"] != revision
                or manifest["repository"] != REPOSITORY
                or not (root / "source" / "README.md").is_file()):
            raise ValueError("Incomplete or inconsistent cache")
        if ref not in (manifest["requested_ref"], revision):
            raise ValueError(f"Cached ref {manifest['requested_ref']!r} does not match {ref!r}")
        return manifest
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise SyncError(f"No valid cache for explicit offline use: {error}") from error


def sync(root=DEFAULT_ROOT, ref="main", offline=False):
    root = Path(root).absolute()
    validate_layout(root)
    with cache_lock(root):
        if offline:
            return cached_manifest(root, ref)
        revision = resolve_revision(ref)
        # Resolve main on every online start, but avoid downloading hundreds of
        # megabytes again when that commit already exists in the validated cache.
        try:
            existing = cached_manifest(root, ref)
        except SyncError:
            existing = None
        if existing is not None and existing["revision"] == revision:
            return existing
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=root / ".releases"))
        candidate = None
        pointer = root / f".current-{uuid.uuid4().hex}"
        try:
            archive = staging / "source.tar.gz"
            digest = download_archive(revision, archive)
            count, total = extract_archive(archive, staging / "source", revision)
            archive.unlink()
            catalog = create_catalog(staging / "source", revision, timestamp)
            manifest = {"schema_version": 1, "repository": REPOSITORY,
                        "requested_ref": ref, "revision": revision, "synchronized_at": timestamp,
                        "archive_sha256": digest, "archive_entries": count,
                        "extracted_bytes": total, "example_count": len(catalog["entries"])}
            write_json(staging / "catalog.json", catalog)
            write_json(staging / "manifest.json", manifest)
            candidate = root / ".releases" / f"{revision}-{uuid.uuid4().hex[:12]}"
            staging.rename(candidate)
            for name in ("source", "manifest.json", "catalog.json"):
                path = root / name
                if not os.path.lexists(path):
                    path.symlink_to(f"current/{name}")
            pointer.symlink_to(f".releases/{candidate.name}")
            os.replace(pointer, root / "current")
            # Old generations are disposable; failure to prune cannot invalidate a refresh.
            for old in (root / ".releases").iterdir():
                if old != candidate and old.is_dir() and not old.is_symlink():
                    shutil.rmtree(old, ignore_errors=True)
            return manifest
        except BaseException:
            if candidate is not None and (root / "current").resolve() != candidate:
                shutil.rmtree(candidate, ignore_errors=True)
            raise
        finally:
            shutil.rmtree(staging, ignore_errors=True)
            pointer.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="Managed cache directory")
    parser.add_argument("--ref", "--revision", default="main", help="Branch, tag, or full 40-character commit SHA")
    parser.add_argument("--offline", action="store_true", help="Explicitly reuse matching previously synchronized cache")
    args = parser.parse_args(argv)
    try:
        manifest = sync(args.root, args.ref, args.offline)
    except (SyncError, OSError, ValueError, KeyError, tarfile.TarError, HTTPError, URLError) as error:
        print(f"Elastic Labs sync failed: {error}. Existing cache was not selected as a fallback. "
              "Retry online, or explicitly use --offline with an existing matching cache.", file=sys.stderr)
        return 1
    mode = "OFFLINE cached" if args.offline else "Synchronized"
    print(f"{mode} Elastic Labs {manifest['revision']} ({manifest['example_count']} examples; "
          f"snapshot {manifest['synchronized_at']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
