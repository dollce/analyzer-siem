#!/usr/bin/env python3
"""On-demand SIEM lifecycle. No third-party Python packages required."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import ssl
import uuid
from scripts.check_version import report_latest
from scripts.source_profiles import load_profiles, create_source_folders, describe_profiles

ROOT = Path(__file__).resolve().parent
SECRET_KEYS = ('ELASTIC_PASSWORD', 'KIBANA_PASSWORD', 'LOGSTASH_PASSWORD',
               'KIBANA_ENCRYPTION_KEY', 'KIBANA_REPORTING_KEY', 'KIBANA_SECURITY_KEY')


def read_env(path):
    result = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or not re.fullmatch(r'[A-Z][A-Z0-9_]*', key.strip()):
            raise ValueError(f'Invalid .env assignment: {key}')
        result[key.strip()] = value.strip().strip('\"\'')
    return result


def init(*, prepare_sources=True):
    # Local configuration must be valid before credentials or folders are created.
    if prepare_sources:
        profiles = load_profiles(ROOT / 'config/source-profiles.json')
        create_source_folders(ROOT, profiles)
    env_path = ROOT / '.env'
    if not env_path.exists():
        text = (ROOT / '.env.example').read_text()
        for key in SECRET_KEYS:
            text = text.replace(f'{key}=GENERATE', f'{key}={secrets.token_hex(24)}')
        # O_EXCL avoids overwriting an existing operator's credentials.
        with os.fdopen(os.open(env_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as out:
            out.write(text)
    env = read_env(env_path)
    for key in SECRET_KEYS:
        if not re.fullmatch(r'[A-Za-z0-9]{32,}', env.get(key, '')):
            raise ValueError(f'{key} must have at least 32 alphanumeric characters; init generates these automatically.')
    for key in ('ES_PORT', 'ES_TRANSPORT_PORT', 'KIBANA_PORT', 'BEATS_PORT', 'SYSLOG_PORT'):
        if not env.get(key, '').isdigit() or not 1 <= int(env[key]) <= 65535:
            raise ValueError(f'{key} must be a TCP/UDP port from 1 to 65535.')
    if len({env[k] for k in ('ES_PORT', 'ES_TRANSPORT_PORT', 'KIBANA_PORT', 'BEATS_PORT', 'SYSLOG_PORT')}) != 5:
        raise ValueError('Host service ports must be distinct.')
    if not re.fullmatch(r'\d+\.\d+\.\d+', env.get('STACK_VERSION', '')):
        raise ValueError('STACK_VERSION must be a pinned stable X.Y.Z version.')
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]+', env.get('COMPOSE_PROJECT_NAME', '')):
        raise ValueError('COMPOSE_PROJECT_NAME must be a lowercase Compose project name.')
    ips = ['127.0.0.1']
    bind = ipaddress.IPv4Address(env.get('BIND_HOST', '0.0.0.0'))
    if not bind.is_unspecified:
        ips.append(str(bind))
    for item in env.get('TLS_EXTRA_IPS', '').split(','):
        if item.strip():
            ips.append(str(ipaddress.ip_address(item.strip())))
    dns = ['elasticsearch', 'localhost', 'host.docker.internal']
    for item in env.get('TLS_EXTRA_DNS', '').split(','):
        if item.strip():
            name = item.strip()
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', name):
                raise ValueError(f'Invalid TLS DNS name: {name}')
            dns.append(name)
    for directory in ('logs', 'live-logs', '.state', '.cache/elastic-labs'):
        (ROOT / directory).mkdir(parents=True, exist_ok=True)
    (ROOT / '.state/instances.yml').write_text(json.dumps({'instances': [
        {'name': 'elasticsearch', 'dns': list(dict.fromkeys(dns)), 'ip': list(dict.fromkeys(ips))}
    ]}, indent=2) + '\n')
    return env


def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def compose(*args, overrides=None, **kwargs):
    # Shell-exported values must not override the checked project .env.
    # Preserve the user's normal Docker context.
    clean_env = os.environ.copy()
    for key in read_env(ROOT / '.env'):
        clean_env.pop(key, None)
    if overrides:
        clean_env.update(overrides)
    return run(['docker', 'compose', '--env-file', str(ROOT / '.env'),
                '-f', str(ROOT / 'compose.yaml'), *args], env=clean_env, **kwargs)


def sync(args):
    command = [sys.executable, str(ROOT / 'scripts/sync_labs.py')]
    if args.offline:
        command.append('--offline')
    if args.ref:
        command += ['--ref', args.ref]
    run(command)


def request(env, path, payload=None):
    """Host-side, CA-verified ES request, honoring a non-default bind address."""
    host = env.get('BIND_HOST', '0.0.0.0')
    if host in ('0.0.0.0', '::'):
        host = 'localhost'
    if ':' in host:
        host = f'[{host}]'
    token = base64.b64encode(f"elastic:{env['ELASTIC_PASSWORD']}".encode()).decode()
    headers = {'Authorization': f'Basic {token}', 'Content-Type': 'application/json'}
    req = urllib.request.Request(f"https://{host}:{env['ES_PORT']}{path}",
                                 data=None if payload is None else json.dumps(payload).encode(), headers=headers)
    context = ssl.create_default_context(cafile=str(ROOT / '.state/ca.crt'))
    with urllib.request.urlopen(req, context=context, timeout=30) as response:
        return json.load(response)


def up(args, env=None):
    env = init() if env is None else env
    mode = 'trial' if args.trial else env.get('LICENSE_MODE', 'basic')
    if mode not in ('basic', 'trial'):
        raise ValueError('LICENSE_MODE must be basic or trial.')
    sync(args)  # Fail before touching the runtime when fresh upstream is unavailable.
    compose('config', '--quiet', overrides={'LICENSE_MODE': mode})
    # Explicit phases rerun auth + bootstrap on every invocation, including resume.
    compose('run', '--rm', '--no-deps', 'certs', timeout=300)
    compose('up', '-d', '--no-deps', '--wait', '--wait-timeout', '600', 'elasticsearch', timeout=660)
    compose('run', '--rm', '--no-deps', 'auth', timeout=300, overrides={'LICENSE_MODE': mode})
    # Refresh Kibana's cached license before installing Trial-only rule types.
    kibana_flags = ['--force-recreate'] if mode == 'trial' else []
    compose('up', '-d', '--no-deps', *kibana_flags, '--wait', '--wait-timeout', '600', 'kibana', timeout=660)
    compose('run', '--rm', '--no-deps', 'bootstrap', timeout=900, overrides={'LICENSE_MODE': mode})
    # Bind-mounted Ruby/profile content can change without Compose detecting it.
    # Recreate so the updated pipeline and source routes are loaded on every up.
    compose('up', '-d', '--no-deps', '--force-recreate', '--wait', '--wait-timeout', '600', 'logstash', timeout=660)
    compose('cp', 'elasticsearch:/usr/share/elasticsearch/config/certs/ca/ca.crt', '.state/ca.crt')
    license_info = request(env, '/_license')['license']
    if license_info['type'] != mode or license_info['status'] != 'active':
        raise RuntimeError(f'Expected an active {mode} license.')
    print(f"Ready: http://localhost:{env['KIBANA_PORT']}/app/security (user: elastic)")
    print('Password: .env ELASTIC_PASSWORD. CA: .state/ca.crt. Drop completed files into logs/.')
    print('Source-specific folders: python3 builder.py sources. Testing guide: docs/detection-testing.md')


def smoke(env):
    """Explicit opt-in writes only a generated marker through the file pipeline."""
    marker = f'lab-smoke-{uuid.uuid4().hex}'
    path = ROOT / 'logs' / f'{marker}.ndjson'
    # No final newline intentionally exercises file-input EOF behavior.
    path.write_text(json.dumps({'message': marker, 'event': {'dataset': 'lab.smoke'},
                                'tags': [marker], '@timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}))
    deadline = time.monotonic() + 120
    try:
        while time.monotonic() < deadline:
            result = request(env, '/logs-lab-*/_search?ignore_unavailable=true',
                             {'query': {'term': {'tags': marker}}, 'size': 1})
            if result['hits']['hits']:
                source = result['hits']['hits'][0]['_source']
                if not source.get('event', {}).get('ingested'):
                    raise RuntimeError('Marker arrived without ingest-pipeline timestamp.')
                print('PASS: logs/ → Logstash → Elasticsearch; final unterminated line and event.ingested verified.')
                return
            time.sleep(2)
        raise RuntimeError('Smoke marker was not found in 120s. Check Logstash logs and its DLQ.')
    finally:
        path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-version-check', action='store_true', help='Skip the informational release lookup')
    sub = parser.add_subparsers(dest='command', required=True)
    sources = sub.add_parser(
        'sources', help='소스별 폴더·인덱스·필드를 확인하는 조회용 명령 (선택 사항)',
        description='sources는 필수 실행 단계가 아닌 조회용 명령입니다.\n'
                    '폴더 생성, SIEM 기동, 로그 주입, 탐지 테스트를 실행하지 않습니다.\n'
                    '폴더는 저장할 인덱스를 정하고, 룰의 Index patterns는 검색 범위를 정합니다.\n'
                    'Custom query는 그 범위에 있는 로그의 실제 ECS 필드로 매칭을 판정합니다.',
        epilog='사용 예시:\n'
               '  python3 builder.py sources                     전체 소스 조회\n'
               '  python3 builder.py sources cloud_defend.alerts 특정 소스 조회\n'
               '  python3 builder.py sources --json              스크립트용 JSON 출력\n'
               '  python3 builder.py sources --help              도움말 확인',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sources.add_argument('name', nargs='?', help='조회할 소스 이름 (생략하면 전체, 예: cloud_defend.alerts)')
    sources.add_argument('--json', action='store_true', help='한글 안내 없이 검증된 프로필 설정만 순수 JSON으로 출력')
    version = sub.add_parser('version', help='Refresh the latest published release notice; never upgrade')
    version.add_argument('--offline', action='store_true', help='Use the existing release cache only')
    for name in ('init', 'check', 'down', 'status', 'smoke', 'rotate-certs'):
        sub.add_parser(name)
    for name in ('up', 'sync-labs'):
        item = sub.add_parser(name)
        item.add_argument('--offline', action='store_true', help='Explicitly reuse a valid existing labs cache')
        item.add_argument('--ref', help='Pin upstream labs to a branch, tag or commit instead of latest main')
        if name == 'up':
            item.add_argument('--trial', action='store_true', help='Activate the official Trial if eligible; opt-in for this invocation')
    destroy = sub.add_parser('destroy', help='Remove this Compose project and all its indexed data/offsets/certificates')
    destroy.add_argument('--yes', action='store_true', required=True, help='Confirm destruction of this project data')
    destroy.add_argument('--purge-cache', action='store_true', help='Also delete downloaded labs source/cache')
    destroy.add_argument('--purge-secrets', action='store_true', help='Also delete .env and generated local state')
    args = parser.parse_args()
    try:
        if args.command == 'sources':
            print(describe_profiles(load_profiles(ROOT / 'config/source-profiles.json'), args.name, args.json))
            return
        if args.command == 'version':
            env_path = ROOT / '.env'
            env = read_env(env_path if env_path.exists() else ROOT / '.env.example')
            report_latest(env['STACK_VERSION'], cache_dir=ROOT / '.cache/version-check',
                          offline=args.offline, force=True)
            return
        # A broken source profile must never prevent stopping/removing the lab.
        env = init(prepare_sources=args.command in ('init', 'up', 'check'))
        if not args.no_version_check:
            report_latest(env['STACK_VERSION'], cache_dir=ROOT / '.cache/version-check',
                          offline=getattr(args, 'offline', False))
        if args.command == 'up':
            up(args, env=env)
            return
        if args.command == 'init':
            print('Initialized .env, certificate inputs and empty source folders. No containers started.')
        elif args.command == 'sync-labs':
            sync(args)
        elif args.command == 'check':
            compose('config', '--quiet')
            run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'])
            run(['ruby', str(ROOT / 'tests/test_normalize.rb')])
            run(['ruby', str(ROOT / 'tests/test_route.rb')])
            run(['bash', '-n', str(ROOT / 'scripts/certs.sh')])
        elif args.command == 'down':
            compose('down', '--remove-orphans', timeout=180)
            print('Stopped; data, offsets, credentials and input logs retained.')
        elif args.command == 'status':
            compose('ps', '-a')
        elif args.command == 'smoke':
            smoke(env)
        elif args.command == 'rotate-certs':
            compose('down', '--remove-orphans', timeout=180)
            compose('run', '--rm', '--no-deps', '--entrypoint', 'bash', 'certs', '-c',
                    'rm -f /certs/elasticsearch/elasticsearch.crt /certs/elasticsearch/elasticsearch.key /certs/instances.sha256')
            print('Leaf certificate cleared; CA and data retained. Run up to issue the updated certificate.')
        elif args.command == 'destroy':
            compose('down', '--volumes', '--remove-orphans', timeout=180)
            (ROOT / '.state/ca.crt').unlink(missing_ok=True)
            if args.purge_cache:
                shutil.rmtree(ROOT / '.cache/elastic-labs', ignore_errors=False)
            if args.purge_secrets:
                (ROOT / '.env').unlink()
                shutil.rmtree(ROOT / '.state')
            print('Project containers/network/volumes removed. Original logs/ and live-logs/ retained.')
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
