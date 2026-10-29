# 사고분석과 탐지 룰 테스트

이 lab은 원본 로그를 보존하면서 데이터 소스별 인덱스에 넣는다. 사고분석은 원래 사건 시각으로 조회하고, 탐지 테스트는 대상 룰의 인덱스·필드·시간 조건을 맞춰 진행한다.

## 룰의 세 가지 개념

| 항목 | 의미 | Container Workload Protection 예 |
| --- | --- | --- |
| Index patterns | 룰이 검색할 인덱스 이름의 범위 | `logs-cloud_defend.alerts-*` |
| Custom query | 그 범위의 문서에서 판정하는 조건 | `event.kind:alert and event.module:cloud_defend` |
| Data Source / Related integrations | 기대하는 원천 제품·통합과 그 데이터 구조에 대한 안내 | Elastic Defend for Containers |

룰 편집 화면에서 데이터 소스로 **Data view**를 선택한 경우에는 해당 뷰가 검색 대상 인덱스를 정한다. 룰의 `Data Source: ...` 태그는 제품 분류이며 폴더를 생성하거나 로그를 변환하는 기능이 아니다.

화면의 `Unable to find matching indices`는 먼저 인덱스 이름을 확인해야 하는 경고다. 이 lab에서는 `logs/cloud_defend.alerts/` → `logs-cloud_defend.alerts-lab-YYYY.MM.dd`로 연결한다. 문서가 실제로 수집되면 위 인덱스 패턴에 포함된다. 폴더나 템플릿만 만들어 둔 상태에서는 빈 인덱스를 생성하지 않는다.

그다음 문서에 쿼리 조건을 만족하는 필드가 있어야 한다. 폴더명만으로 임의 텍스트를 경보로 만들지 않는다. 이 룰은 이미 생성된 컨테이너 경보를 SIEM 경보로 연결하는 룰이다. 일반 컨테이너 로그에서 공격 행위를 처음 판정하는 테스트와는 목적이 다르다. [공식 룰 정의](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/cloud_defend/container_workload_protection)

## 1. 소스와 입력 준비

```bash
python3 builder.py sources
python3 builder.py sources cloud_defend.alerts
python3 builder.py sources --json
python3 builder.py init
```

`sources`는 설정 조회만 수행한다. `init`은 등록 소스의 빈 `logs/<source>/`, `live-logs/<source>/` 폴더를 준비한다. 원본 파일은 수정하지 않는다.

```text
logs/
├── cloud_defend.alerts/
│   └── case-001/alerts.ndjson
├── windows.sysmon_operational/
│   └── case-001/sysmon.ndjson
└── generic/
    └── case-001/application.log
```

`logs/case-001/cloud_defend.alerts/`는 첫 폴더가 미등록 소스이므로 `logs-lab-*`로 들어간다. 사건 폴더는 소스 폴더 아래에 둔다. 데이터 소스별 출력은 일반 인덱스이며 Fleet data stream을 생성하거나 통합 패키지를 설치하지 않는다. 따라서 파일 수집만으로 Related integrations의 `Not installed` 표시가 바뀌지는 않는다.

제품별 원시 JSON과 ECS JSON은 다를 수 있다. Sysmon EVTX/XML, 원시 CloudTrail JSON 배열, CSV, 여러 줄 로그는 해당 제품의 파서로 ECS JSONL로 변환해야 한다. 프로필의 `required_fields`는 입력 준비를 위한 확인 목록이며 모든 룰의 필수 필드를 망라하거나 데이터 적합성을 자동 검증하는 스키마가 아니다. 선택한 룰의 Required fields와 전체 쿼리를 함께 확인한다.

선택한 룰이 `winlogbeat-*` 같은 다른 인덱스만 조회한다면 이 lab의 `logs-windows.sysmon_operational-lab-*`를 자동으로 검색하지 않는다. 해당 룰의 테스트 복제본에 실제 lab 인덱스 패턴을 지정한다. 모든 룰의 인덱스 목록을 일괄 변경하지 않는다.

## 2. 사고분석

완료된 파일은 `.partial`로 복사한 뒤 이름을 변경한다. 아래 명령은 사용자가 실행하면 해당 파일을 수집 대상으로 만든다.

```bash
mkdir -p logs/windows.sysmon_operational/case-001
cp /path/to/ecs-sysmon.ndjson logs/windows.sysmon_operational/case-001/events.ndjson.partial
mv logs/windows.sysmon_operational/case-001/events.ndjson.partial logs/windows.sysmon_operational/case-001/events.ndjson
```

Discover에서 `Lab logs`를 선택하고 사건의 원래 시간 범위로 조회한다. 모든 소스를 함께 보면서 다음 필드를 활용한다.

| 필드 / 데이터 뷰 | 사용 목적 |
| --- | --- |
| `@timestamp` / `Lab logs` | 원래 사건 시각 기준 조사 |
| `event.ingested` / `Lab logs — ingest time` | 방금 수집한 과거 로그 찾기 |
| `event.original` | 입력에 있던 원문. 없을 때는 원본 입력 메시지로 채움 |
| `lab.source_profile` | 폴더에서 선택된 소스 |
| `lab.input_path` | 이 lab의 파일 입력 경로 |
| 원본 `log.file.path` | ECS JSON에 포함된 원래 로그 경로 |

기존 `event.dataset`은 유지하고, 등록된 소스에서 비어 있을 때만 프로필의 dataset을 넣는다. 일반 텍스트도 검색할 수 있지만 필요한 의미 필드가 없으면 해당 탐지 쿼리와 일치하지 않는다. 사고 시각을 현재 시각으로 덮어쓰지 않는다.

## 3. 양성·음성 대조 데이터로 탐지 테스트

[예제 파일](../examples/cloud_defend.alerts.ndjson)은 실제 사고 로그가 아닌 합성 데이터 두 건이다. 두 문서 모두 `event.module=cloud_defend`이며 다음 한 가지 조건이 다르다.

| `event.id` | `event.kind` | 위 KQL의 기대 결과 |
| --- | --- | --- |
| `cloud-defend-positive-01` | `alert` | 매칭 |
| `cloud-defend-negative-01` | `event` | 비매칭 |

두 문서의 원래 시각은 `2024-01-15T10:00:00Z`와 `2024-01-15T10:00:01Z`이다. 수집 후에도 이 시각이 유지되고, `event.ingested`만 현재 수집 시각으로 기록된다. 예제 파일은 자동 주입되지 않는다.

SIEM을 실행한 뒤 사용자가 다음 명령을 실행하면 예제 두 건이 수집된다.

```bash
mkdir -p logs/cloud_defend.alerts/demo
cp examples/cloud_defend.alerts.ndjson logs/cloud_defend.alerts/demo/controls.ndjson.partial
mv logs/cloud_defend.alerts/demo/controls.ndjson.partial logs/cloud_defend.alerts/demo/controls.ndjson
```

1. Discover에서 `Lab logs — ingest time`과 최근 시간 범위를 선택한다. KQL `tags:lab-cloud-defend-fixture`로 두 문서를 찾고 `_index`가 `logs-cloud_defend.alerts-lab-*`인지 확인한다.
2. KQL `tags:lab-cloud-defend-fixture and event.kind:alert and event.module:cloud_defend`로 양성 문서만 남는지 확인한다. 이 단계는 쿼리 일치 검사이며 탐지 엔진의 실제 경보 생성 검사는 아니다.
3. 테스트할 룰을 복제해 명확한 테스트 이름을 부여한다. 예외·suppression·필터까지 포함해 원본 룰과 비교하고, 테스트 데이터만 대상으로 삼으려면 복제본에 위 fixture 태그 조건을 추가한다. 모든 prebuilt 룰을 켤 필요는 없다.
4. 복제본의 Rule Preview를 사용한다. 원래 사건 시각으로 검색하는 룰은 2024-01-15의 범위를, `event.ingested`를 Timestamp override로 쓰는 룰은 실제 수집 시각을 포함하는 범위를 선택한다. Preview는 룰을 저장하기 전에 결과를 살펴보는 기능이다. [공식 Rule Preview 안내](https://www.elastic.co/docs/solutions/security/detect-and-alert/using-the-rule-ui)
5. 정기 실행까지 확인하려면 복제본을 활성화하고 실행 주기와 추가 look-back이 수집 시각을 포함하도록 설정한 뒤 Execution results와 Alerts를 확인한다. 테스트가 끝나면 복제본을 비활성화하거나 삭제한다.

첨부 화면의 Container Workload Protection은 `event.ingested` override를 사용한다. 설치된 룰 버전의 Definition에서 같은 설정인지 확인한다. 과거 로그를 오늘 넣은 경우에도 해당 수집 시각을 대상으로 검색할 수 있다. 이미 검색 구간이 지난 뒤 룰을 활성화했다면 Preview 범위를 넓히거나 새 테스트 입력으로 다시 수집한다. 데이터 뷰를 바꾸는 것만으로 룰의 timestamp 설정이 바뀌지는 않는다.

양성 문서만 쿼리에 매칭되는 것이 대조 테스트의 기준이다. 최종 경보 수는 기존 중복 경보, suppression, 예외, 실행 구간 등에 영향을 받는다. 합성 입력의 성공은 수집 경로와 해당 룰 동작에 대한 검증이며, 실제 센서가 공격을 탐지했다는 증거가 아니다.

EQL sequence, threshold, new terms, indicator match, ML 룰은 추가 이벤트·상관 키·이력·indicator·ML 작업이 필요할 수 있다. EQL의 이벤트 순서를 정하는 timestamp field와 검색 시간 범위의 timestamp override는 별개다. `event.ingested`만 지정해서 모든 과거 사건의 상관분석이 동일하게 재현된다고 가정하지 않는다. [공식 EQL 필드 설명](https://www.elastic.co/docs/solutions/security/detect-and-alert/eql)

## 4. 결과가 없을 때

| 증상 | 확인할 항목 |
| --- | --- |
| matching indices 경고 | 등록 소스 폴더 위치, Logstash 오류, 실제 `_index`, 룰의 index patterns 또는 data view |
| Discover에서 로그가 안 보임 | `@timestamp`와 `event.ingested` 중 현재 뷰의 시간 필드, 시간 범위, 파일 권한·확장자·DLQ |
| `lab_unknown_source_profile` 태그 | `logs/` 바로 아래 폴더가 등록 이름과 일치하는지 확인 |
| `lab_source_dataset_mismatch` 태그 | 폴더와 원본 `event.dataset`을 확인. 자동으로 덮어쓰지 않으므로 적절한 폴더로 다시 준비 |
| 문서는 있지만 쿼리 매칭 0 | ECS 필드 구조·자료형·실제 값, 쿼리 언어와 전체 조건 |
| 쿼리는 맞지만 Alerts가 없음 | 룰 활성화 여부, 실행 결과, timestamp override, look-back, 예외·suppression·라이선스·외부 의존성 |
| 파일을 다시 넣었는데 변화 없음 | sincedb가 이미 읽은 파일인지 확인. 완료 파일 재실험은 새 파일로 복사 |

`down`은 데이터와 수집 위치를 유지한다. `destroy --yes`는 lab 인덱스와 수집 위치를 삭제하지만 원본 파일은 남긴다. 다시 시작하면 남아 있는 파일이 재수집되므로 필요 없는 합성 입력은 사용자가 `logs/` 밖으로 옮겨 둔다. 기존 `logs-lab-*` 문서는 폴더 구조를 바꿔도 자동 이동하지 않는다.

## 5. 새 소스 등록

[config/source-profiles.json](../config/source-profiles.json)의 `profiles`에 항목을 추가한다. 예를 들어 `panw.panos`를 추가할 경우:

```json
"panw.panos": {
  "description": "ECS로 변환한 PAN-OS 이벤트",
  "index_prefix": "logs-panw.panos-lab",
  "dataset": "panw.panos",
  "rule_index_patterns": ["logs-panw.panos-*"],
  "required_fields": ["@timestamp", "event.module", "event.action"]
}
```

소스 이름은 소문자로 시작하며 소문자·숫자·밑줄과 점으로 구분한 이름을 사용한다. 경로 구분자, wildcard, `..`은 사용할 수 없다. `generic`은 반드시 유지하며 인덱스 prefix는 `logs-lab`, dataset은 `lab.generic`이다. 다른 소스는 prefix를 `logs-<이름>-lab`, dataset을 `<이름>`과 정확히 일치시킨다.

`rule_index_patterns`는 대응할 룰의 패턴을 설명하는 안내이며 실제 출력은 `index_prefix`로 결정된다. `required_fields`도 안내 목록이다. 새 제품의 파서·추가 매핑과 선택한 룰의 요구 필드는 별도로 점검한다.

```bash
python3 builder.py sources panw.panos
python3 builder.py check
bash scripts/check_logstash.sh
python3 builder.py down
python3 builder.py up
```

Trial 사용 중이면 마지막 명령은 `up --trial`로 실행한다. 재기동 시 등록된 소스에서 출력 인덱스 템플릿·수집 계정 권한·두 데이터 뷰를 함께 구성한다. 이때 기존 로그나 룰의 필드를 재작성하지 않는다.
