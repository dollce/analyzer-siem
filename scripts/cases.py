"""Local case registration shared by the CLI and SIEM bootstrap."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import tempfile

try:
    from scripts.source_profiles import unique_object
except ModuleNotFoundError as error:
    if error.name not in ('scripts', 'scripts.source_profiles'):
        raise
    from source_profiles import unique_object

CASE_NAME = re.compile(r'[a-z][a-z0-9_]{0,63}\Z')
MAX_CASES = 128


def validate_case_name(name, profiles):
    if not isinstance(name, str) or not CASE_NAME.fullmatch(name):
        raise ValueError('case명은 영문 소문자로 시작하는 소문자·숫자·밑줄 1~64자로 지정하세요.')
    if name in profiles:
        raise ValueError(f'case명은 등록된 소스 이름과 같을 수 없습니다: {name}')
    return name


def load_cases(path, profiles):
    """Missing registry is an existing installation with no registered cases."""
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Case registry must not be a symbolic link.')
    try:
        with path.open('rb') as source:
            raw = source.read(65537)
    except FileNotFoundError:
        return []
    if len(raw) > 65536:
        raise ValueError('Case registry exceeds 64 KiB.')
    data = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(data, dict) or set(data) != {'version', 'cases'} or type(data['version']) is not int or data['version'] != 1:
        raise ValueError('Case registry requires version 1 and cases.')
    names = data['cases']
    if not isinstance(names, list) or len(names) > MAX_CASES:
        raise ValueError(f'Case registry supports at most {MAX_CASES} cases.')
    for name in names:
        validate_case_name(name, profiles)
    if len(set(names)) != len(names):
        raise ValueError('Duplicate case name in registry.')
    return names


def case_index_patterns(profiles, case_name):
    validate_case_name(case_name, profiles)
    # No wildcard in the case segment. This also includes generic's special prefix.
    return [f"{profile['index_prefix']}-case_{case_name}-*" for profile in profiles.values()]


def check_directories(paths):
    for path in paths:
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ValueError(f'Expected an ordinary directory: {path}')


@contextmanager
def registry_lock(root):
    directory = Path(root) / '.cases'
    check_directories([directory])
    directory.mkdir(mode=0o755, exist_ok=True)
    # Serialize parallel case-init calls; never follow a lock-file symlink.
    descriptor = os.open(directory / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield directory / 'registry.json'


def write_registry(path, names):
    """Publish a complete file; directory bind mounts observe the replacement."""
    descriptor, temporary = tempfile.mkstemp(prefix='.registry-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as target:
            os.fchmod(target.fileno(), 0o644)
            json.dump({'version': 1, 'cases': sorted(names)}, target, indent=2)
            target.write('\n')
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def ensure_registry(root, profiles):
    """Prepare the Compose mount without registering or reclassifying old folders."""
    with registry_lock(root) as path:
        names = load_cases(path, profiles)
        if not path.exists():
            write_registry(path, names)
    return names


def init_case(root, name, profiles):
    """Prepare one case without credentials, service calls or source-file writes."""
    validate_case_name(name, profiles)
    root = Path(root)
    destinations = [root / base for base in ('logs', 'live-logs')]
    destinations += [root / base / name for base in ('logs', 'live-logs')]
    destinations += [root / base / name / source for base in ('logs', 'live-logs') for source in profiles]
    check_directories(destinations)
    with registry_lock(root) as path:
        names = load_cases(path, profiles)
        if name not in names and len(names) >= MAX_CASES:
            raise ValueError(f'Case registry supports at most {MAX_CASES} cases.')
        check_directories(destinations)
        for directory in destinations:
            directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        if name not in names:
            write_registry(path, names + [name])
    return case_index_patterns(profiles, name)
