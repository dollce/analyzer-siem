"""Validated local source folders and their lab-owned index namespaces."""
import json
from pathlib import Path
import re

DEFAULT_PATH = Path(__file__).resolve().parents[1] / 'config/source-profiles.json'
NAME = re.compile(r'[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*\Z')
FIELD = re.compile(r'(?:@timestamp|[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*)\Z')
KEYS = {'description', 'index_prefix', 'dataset', 'rule_index_patterns', 'required_fields'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate source profile key: {key}')
        result[key] = value
    return result


def load_profiles(path=DEFAULT_PATH):
    """Reject ambiguous paths/destinations before starting or configuring services."""
    with Path(path).open('rb') as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError('Source profile configuration exceeds 64 KiB.')
    data = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(data, dict) or set(data) != {'version', 'profiles'} or type(data['version']) is not int or data['version'] != 1:
        raise ValueError('Source profile configuration requires version 1 and profiles.')
    profiles = data['profiles']
    if not isinstance(profiles, dict) or not 1 <= len(profiles) <= 64 or 'generic' not in profiles:
        raise ValueError('Source profiles require generic and at most 64 entries.')
    for name, profile in profiles.items():
        if not NAME.fullmatch(name) or len(name) > 100:
            raise ValueError(f'Invalid source folder name: {name}')
        if not isinstance(profile, dict) or not KEYS <= profile.keys() or profile.keys() - KEYS - {'example_query'}:
            raise ValueError(f'Invalid source profile fields: {name}')
        prefix = 'logs-lab' if name == 'generic' else f'logs-{name}-lab'
        dataset = 'lab.generic' if name == 'generic' else name
        if profile['index_prefix'] != prefix or profile['dataset'] != dataset:
            raise ValueError(f'{name}: index_prefix must be {prefix} and dataset must be {dataset}.')
        if not isinstance(profile['description'], str) or not profile['description'].strip() or len(profile['description']) > 1000:
            raise ValueError(f'{name}: description must be nonempty text of at most 1000 characters.')
        patterns = profile['rule_index_patterns']
        if not isinstance(patterns, list) or not patterns or len(patterns) > 16 or any(
            not isinstance(p, str) or len(p) > 200 or not re.fullmatch(r'[a-z0-9_.*?-]+', p) for p in patterns
        ):
            raise ValueError(f'{name}: rule_index_patterns must be a list of index patterns.')
        fields = profile['required_fields']
        if not isinstance(fields, list) or not fields or len(fields) > 64 or any(
            not isinstance(f, str) or len(f) > 200 or not FIELD.fullmatch(f) for f in fields
        ) or len(set(fields)) != len(fields):
            raise ValueError(f'{name}: required_fields must contain unique ECS field paths.')
        if 'example_query' in profile:
            query = profile['example_query']
            if not isinstance(query, dict) or set(query) != {'language', 'query'} or query['language'] not in ('kuery', 'lucene', 'eql') or not isinstance(query['query'], str) or not 1 <= len(query['query']) <= 4096:
                raise ValueError(f'{name}: invalid example_query.')
    return profiles


def index_patterns(profiles):
    """Only this lab's namespaces; rule hints do not grant index privileges."""
    return [profile['index_prefix'] + '-*' for profile in profiles.values()]


def create_source_folders(root, profiles):
    """Create empty folders without following links out of the input roots."""
    root = Path(root)
    destinations = [root / base for base in ('logs', 'live-logs')]
    destinations += [root / base / name for base in ('logs', 'live-logs') for name in profiles]
    # Validate every destination first so an invalid layout is not half initialized.
    for path in destinations:
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ValueError(f'Expected an ordinary source directory: {path}')
    for path in destinations:
        path.mkdir(parents=True, exist_ok=True)


def describe_profiles(profiles, name=None, as_json=False):
    if name is not None and name not in profiles:
        raise ValueError(f'Unknown source profile: {name}. Run builder.py sources for available folders.')
    selected = {name: profiles[name]} if name is not None else profiles
    if as_json:
        return json.dumps({'version': 1, 'profiles': selected}, ensure_ascii=False, indent=2)
    lines = ['Source folders → lab indices (ECS fields still determine rule matches)']
    for key, profile in selected.items():
        lines.append(f"\nlogs/{key}/ → {profile['index_prefix']}-YYYY.MM.dd")
        lines.append(f"  live-logs/{key}/ uses the same route; {profile['description']}")
        lines.append('  Rule index examples: ' + ', '.join(profile['rule_index_patterns']))
        lines.append('  Fields to inspect (rule-specific requirements may add more): ' + ', '.join(profile['required_fields']))
        if 'example_query' in profile:
            query = profile['example_query']
            lines.append(f"  Example {query['language']}: {query['query']}")
    lines += ['', 'Folders route data; they do not install integrations or turn text into product-specific ECS events.',
              'Root files and unknown folders use logs-lab-*. Original @timestamp is retained.',
              'Run builder.py init to create empty source folders. See docs/detection-testing.md.']
    return '\n'.join(lines)
