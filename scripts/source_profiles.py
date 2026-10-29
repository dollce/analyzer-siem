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
        raise ValueError(f'등록되지 않은 소스: {name}. python3 builder.py sources로 사용 가능한 폴더를 확인하세요.')
    selected = {name: profiles[name]} if name is not None else profiles
    if as_json:
        return json.dumps({'version': 1, 'profiles': selected}, ensure_ascii=False, indent=2)
    lines = [
        'sources는 필수 단계가 아닌 조회용 명령입니다.',
        '등록된 폴더·출력 인덱스·ECS 필드 안내를 확인합니다. 폴더명을 이미 알고 있다면 실행하지 않아도 됩니다.',
        '이 명령은 폴더 생성, SIEM 기동, 로그 주입, 탐지 테스트를 실행하지 않습니다.',
        '',
        '폴더·인덱스·쿼리의 관계',
        '  1. logs/<소스>/ 폴더가 로그를 저장할 출력 인덱스를 정합니다.',
        '  2. 룰의 Index patterns에 그 인덱스가 포함되어야 검색 대상이 됩니다.',
        '  3. Custom query는 로그의 실제 ECS 필드 값을 검사합니다. 인덱스가 맞아도 쿼리 조건을 충족해야 합니다.',
        '  폴더명만으로 쿼리에 필요한 필드 값을 채우거나 탐지 성공을 보장하지 않습니다.',
        '',
        '사용 예시',
        '  python3 builder.py sources                       # 전체 소스 조회',
        '  python3 builder.py sources cloud_defend.alerts   # 특정 소스 조회',
        '  python3 builder.py sources --json                # 스크립트용 순수 JSON 출력',
        '  python3 builder.py sources --help                # 명령 문법 확인',
        '',
        '등록된 소스 안내',
    ]
    for key, profile in selected.items():
        lines.append(f"\n{key}: {profile['description']}")
        lines.append(f"  완료 파일: logs/{key}/ → {profile['index_prefix']}-YYYY.MM.dd")
        lines.append(f"  추가 기록 파일: live-logs/{key}/ → 같은 출력 인덱스")
        lines.append('  룰의 Index patterns 예: ' + ', '.join(profile['rule_index_patterns']))
        lines.append('  확인할 ECS 필드: ' + ', '.join(profile['required_fields']))
        if 'example_query' in profile:
            query = profile['example_query']
            language = {'kuery': 'KQL', 'lucene': 'Lucene', 'eql': 'EQL'}[query['language']]
            lines.append(f"  Custom query 예 ({language}): {query['query']}")
    lines += [
        '',
        '필드 목록과 쿼리는 준비를 위한 안내입니다. 실제 룰의 전체 조건과 검색 시간 범위도 확인하세요.',
        '폴더 설정은 통합 패키지를 설치하거나 일반 텍스트를 제품별 ECS 이벤트로 변환하지 않습니다.',
        'logs/ 바로 아래 파일과 미등록 폴더는 logs-lab-*로 수집하며, 원본 @timestamp는 보존합니다.',
        '빈 폴더 준비: python3 builder.py init / SIEM 실행: python3 builder.py up (Trial 선택 시 up --trial)',
        '실제 매칭 확인: Kibana 검색·Rule Preview. 자세한 절차: docs/detection-testing.md',
    ]
    return '\n'.join(lines)
