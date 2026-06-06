# Detection Scenario Platform — Architecture Specification

> **Canonical location:** [detection-scenario-platform/ARCHITECTURE_SPEC.md](../../detection-scenario-platform/ARCHITECTURE_SPEC.md) (v0.3.0+)  
> 본 파일은 Phase 0 스냅샷이다. Execution Provider Architecture는 canonical 문서를 참조한다.

**문서 버전:** 0.1.0 (Phase 0)  
**상태:** Design only — no implementation

---

## 1. Overview

DSP는 권한 있는 PoC 환경에서 탐지 시나리오를 **실행·기록·검증·리포트**하는 플랫폼이다. 모든 판정은 Event Store를 유일한 진실원(SOT)으로 사용한다.

### 1.1 설계 목표

| ID | 목표 |
|----|------|
| G1 | Execution = Validation = Reporting (단일 경로) |
| G2 | 시나리오 플러그인으로 확장, 코어 수정 최소화 |
| G3 | Traffic 생성과 Detection 확인 분리 |
| G4 | 3년간 vendor·시나리오 확장 가능 |
| G5 | Safe PoC — lab subnet, volume cap, no malware |

---

## 2. Component Map

```
                    ┌──────────────┐
                    │    Runner    │  CLI: dsp run / validate / report
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
     ┌────────────┐ ┌────────────┐ ┌──────────────┐
     │  Scenario  │ │   Target   │ │    Plugin    │
     │   Engine   │ │   Engine   │ │    Loader    │
     └─────┬──────┘ └─────┬──────┘ └──────┬───────┘
           │              │               │
           │    ┌─────────┴─────────┐     │
           │    ▼                   ▼     │
           │  TargetSet         ScenarioRegistry
           │  (CIDR-safe)       (auto-discover)
           ▼
     ┌─────────────────────────────────────┐
     │         Scenario Plugins            │
     │  dns_tunnel │ dga │ http │ ssh │ sql │
     └─────────────────┬───────────────────┘
                       │ append events
                       ▼
              ┌─────────────────┐
              │   Event Store   │  ← SINGLE SOURCE OF TRUTH
              │  (SQLite/JSONL) │
              └────────┬────────┘
                       │
           ┌───────────┴───────────┐
           ▼                       ▼
    ┌──────────────┐       ┌──────────────┐
    │  Validation  │       │  Reporting   │
    │    Engine    │       │    Engine    │
    └──────┬───────┘       └──────┬───────┘
           │                      │
           └──────────┬───────────┘
                      ▼
              RunResult / Report
                      │
                      ▼ (optional, future)
              ┌──────────────┐
              │  Detection   │
              │   Adapters   │  Stellar / Defender / Splunk …
              └──────────────┘
```

---

## 3. Component Specifications

### 3.1 Runner

**책임:** CLI 진입점, run lifecycle 관리, 구성 로드.

| 명령 | 동작 |
|------|------|
| `dsp run` | 시나리오 실행 → Event Store 기록 → validate → report |
| `dsp validate` | 기존 run_id Event Store만으로 재검증 |
| `dsp report` | 기존 run_id 리포트 재생성 |
| `dsp list-scenarios` | Plugin Loader가 등록한 시나리오 목록 |

**Runner는 하지 않는 것:**

- stdout/grep으로 성공 판정
- 시나리오별 프로토콜 로직 (플러그인에 위임)
- synthetic score 계산

**Run Context (모든 컴포넌트 공유):**

```python
@dataclass
class RunContext:
    run_id: str              # UUID or timestamp slug
    target_net: str          # e.g. "10.10.10.0/24"
    started_at: datetime
    config: RunConfig
    event_store: EventStore  # injected — never recreated mid-run
    dry_run: bool
```

### 3.2 Scenario Engine

**책임:** 등록된 시나리오를 순서·병렬 정책에 따라 실행.

**Lifecycle per scenario:**

```
prepare(ctx, targets) → execute(ctx, targets) → [events appended]
                              ↓
                    ValidationEngine.validate(scenario_id)
                              ↓
                    scenario.summarize(ctx) → ScenarioSummary
```

**실행 정책:**

- 기본: sequential (레거시 overlap 실패 교훈)
- 옵션: `max_parallel_scenarios` (Phase 2+, Event Store write lock 보장)
- fail-fast: Target Engine이 빈 target set 반환 시 skip (실패 아님, `skipped` 상태)

**Scenario Engine은 성공을 선언하지 않는다.** Validation Engine만 `success|partial|failed|skipped` 반환.

### 3.3 Target Engine

**책임:** lab 범위 내 실행 대상 선정·검증.

| 기능 | 설명 |
|------|------|
| CIDR enforcement | `target_net` 밖 IP/URL 거부 |
| Discovery (optional) | port scan, reachability — **preflight only** |
| TargetSet | 시나리오별 필요 타입 (`dns_resolver`, `http_host`, `ssh_host`) |

**레거시 교훈:** Discovery 결과가 0이어도 stage_result Success 금지. Target 없으면 시나리오 `skipped`, Event Store에 `target_unavailable` 이벤트 1건 기록.

```json
{
  "scenario": "http_followup",
  "event": "scenario_skipped",
  "reason": "no_reachable_http_targets",
  "target_net": "10.10.10.0/24"
}
```

### 3.4 Event Store

**책임:** append-only 이벤트 저장, run_id 격리, summary 쿼리 API.

상세: [EVENT_STORE_SPEC.md](./EVENT_STORE_SPEC.md)

**핵심 API (개념):**

```python
class EventStore:
    def append(self, event: Event) -> None: ...
    def query(self, filters: EventQuery) -> list[Event]: ...
    def aggregate(self, spec: AggregateSpec) -> dict[str, int | float]: ...
    def run_event_count(self, run_id: str, scenario: str) -> int: ...
```

### 3.5 Validation Engine

**책임:** Event Store 집계만으로 시나리오·run 판정.

**입력:** `run_id`, `scenario_id` (또는 전체 run)  
**출력:** `ValidationResult(decision, reason, metrics, fail_fast_codes)`

**금지:** stdout, log file grep, overlap env, planned counters

**판정 흐름:**

```
1. EventStore.aggregate(scenario_validation_spec)
2. apply_thresholds(metrics) → decision
3. check_fail_fast_invariants(metrics) → CODE_FAILURE if violated
4. return ValidationResult
```

시나리오별 threshold는 `scenarios/<id>/manifest.yaml`의 `validation` 블록에 선언 (코드 하드코딩 최소화).

### 3.6 Reporting Engine

**책임:** Event Store + ValidationResult → human/machine report.

**입력:** Event Store, ValidationResult[], RunContext  
**출력:** Markdown / JSON report

**금지:**

- stdout 파싱
- synthetic detection score
- stage_result log를 success 근거로 사용

**리포트 섹션:**

1. Run metadata (run_id, target_net, scenarios, duration)
2. Per-scenario validation table (decision, reason, key metrics)
3. Event samples (최대 N건, PII 없음)
4. Fail-fast codes (있을 경우)
5. (Optional) Detection adapter results — 별도 섹션, traffic validation과 분리

### 3.7 Plugin Loader

**책임:** `scenarios/` 디렉터리 스캔, manifest 로드, Scenario 클래스 등록.

**발견 규칙:**

```
scenarios/<scenario_id>/
├── manifest.yaml      # required
├── scenario.py        # Scenario subclass
└── executor.py        # optional: traffic logic
```

`manifest.yaml`의 `id`가 canonical scenario_id. 폴더명과 일치 필수.

### 3.8 Detection Model Adapters (Future)

Traffic 생성과 **완전 분리**. Validation Engine의 traffic success와 독립.

```python
class DetectionAdapter(Protocol):
    def poll_detections(
        self, ctx: RunContext, scenario_id: str, window: TimeWindow
    ) -> DetectionResult: ...
```

| Adapter | Phase |
|---------|-------|
| `stellar` | Phase 3 |
| `defender`, `sentinelone`, `splunk` | Phase 4+ |

리포트에 **Traffic Validation**과 **Detection Confirmation**을 별도 표로 표시. 혼합 금지.

---

## 4. Data Flow

### 4.1 End-to-End Run Flow

```mermaid
sequenceDiagram
    participant U as Operator
    participant R as Runner
    participant T as Target Engine
    participant S as Scenario Engine
    participant P as Scenario Plugin
    participant E as Event Store
    participant V as Validation Engine
    participant Rep as Reporting Engine

    U->>R: dsp run --scenarios dns_tunnel,dga
    R->>E: init_run(run_id)
    R->>T: resolve_targets(target_net)
    T-->>R: TargetSet
    loop each scenario
        R->>S: run_scenario(id, targets)
        S->>P: prepare(ctx, targets)
        S->>P: execute(ctx, targets)
        P->>E: append(events...)
        Note over P: execute() returns void,<br/>never "success"
    end
    R->>V: validate_run(run_id)
    V->>E: aggregate per scenario
    V-->>R: ValidationResult[]
    R->>Rep: generate_report(run_id, results)
    Rep->>E: query samples
    Rep-->>U: report.md + exit code
```

### 4.2 Exit Code Policy

| Code | 의미 |
|------|------|
| 0 | 모든 requested scenario `success` |
| 1 | 하나 이상 `failed` 또는 `CODE_FAILURE` |
| 2 | partial success (일부 success, 일부 failed/skipped) |
| 3 | configuration / safety violation |

---

## 5. Event Flow

### 5.1 Event Lifecycle

```
[Scenario execute]
    │
    ├─► scenario_started     (status: info)
    ├─► query_sent / request_sent / auth_attempted  (status: sent)
    ├─► query_response / http_response / auth_failed (status: outcome)
    ├─► scenario_error       (status: error)
    └─► scenario_completed   (status: info)
         │
         ▼
    Event Store (append-only)
         │
         ├─► ValidationEngine.aggregate()
         └─► ReportingEngine.sample()
```

### 5.2 Event 작성 규칙

| 규칙 | 설명 |
|------|------|
| E1 | 모든 네트워크 액션은 1 action = 1 event (batch 금지, debug 제외) |
| E2 | `run_id` 필수 — cross-run 오염 방지 |
| E3 | `scenario` + `event` + `status` 삼각형으로 query 가능 |
| E4 | `evidence`는 구조화 문자열 또는 JSON — free text 최소화 |
| E5 | execute() 종료 시 `scenario_completed` 필수 (crash 시 Runner가 `scenario_aborted` 기록) |

### 5.3 레거시 TSV → DSP Event 매핑

| Legacy TSV field | DSP Event field |
|------------------|-----------------|
| `module` | `scenario` |
| `stage` | `stage` |
| `action` | `event` |
| `artifact` | `artifact` |
| `status` | `status` |
| `evidence_value` | `evidence` |
| `target` | `target` |

---

## 6. Validation Flow

### 6.1 Per-Scenario Validation Pipeline

```
EventStore.aggregate(
    run_id=...,
    scenario=...,
    metrics=[sent, nxdomain, responses, ...]
)
    ↓
Threshold check (from manifest.yaml)
    ↓
Fail-fast invariants
    ↓
ValidationResult
```

### 6.2 초기 시나리오 Thresholds (레거시 검증 기반)

| Scenario | Success Condition | Partial | Failed |
|----------|-------------------|---------|--------|
| `dns_tunnel` | `query_sent >= 1` | — | `query_sent == 0` |
| `dga` | `nxdomain >= 300 && resolvable >= 10` && `base_domain == xdr.ooo` | thresholds 50% | no events or wrong base |
| `http_followup` | `attempted >= 1 && responses >= 1` | attempted only | no events |
| `ssh_failure` | `auth_attempted >= 1` | — | no events |
| `sql_injection` | `injection_request_sent >= 1` | — | no events |

**강화 메트릭 (권장, success 추가 조건):**

- DNS Tunnel: `idx_pattern_ratio >= 0.8`, `avg_label_length >= 40`
- DGA: full run `nx >= 500 && resolvable >= 30`

### 6.3 Fail-Fast Invariants

| Code | Condition |
|------|-----------|
| `SOT_EMPTY_AFTER_EXECUTE` | stage executed + event_count=0 |
| `SOT_SENT_WITHOUT_ARTIFACT` | sent>0 + unique_artifact=0 |
| `STDOUT_ONLY_REJECTED` | (test only) stdout claims success, events=0 |
| `COUNTER_IMPOSSIBLE` | responses > attempted |

### 6.4 Validation vs Detection

| | Traffic Validation | Detection Confirmation |
|--|-------------------|----------------------|
| 데이터 소스 | Event Store | Vendor API / SIEM |
| Phase 1 | **필수** | 선택 |
| 리포트 | Primary | Secondary appendix |
| 실패 의미 | 트래픽 미생성 | 센서 미탐지 (환경 이슈 가능) |

---

## 7. Reporting Flow

```
ValidationResult[] + EventStore
    │
    ├─► Executive summary (counts: success/failed/skipped)
    ├─► Scenario table
    │     scenario | decision | reason | query_sent | ...
    ├─► Event samples (top 5 per scenario)
    ├─► Fail-fast section
    └─► Raw JSON appendix (machine-readable)
```

**레거시 실패 방지:** 리포트의 scenario row는 **반드시** ValidationResult에서만 생성. Executor stdout은 "Debug Log" 부록에만 포함 가능.

---

## 8. Plugin Architecture

### 8.1 Discovery & Registration

```python
# Plugin Loader pseudocode
for path in scenarios_dir.iterdir():
    manifest = load_yaml(path / "manifest.yaml")
    module = importlib.import_module(f"scenarios.{path.name}.scenario")
    cls = module.Scenario
    registry.register(manifest.id, cls, manifest)
```

### 8.2 Manifest-Driven Configuration

시나리오별 변수는 manifest에 선언. Runner가 `RunConfig`로 merge.

```yaml
# scenarios/dns_tunnel/manifest.yaml (example)
id: dns_tunnel
version: "1.0.0"
title: DNS Tunnel — idx-pattern UDP/53
targets:
  requires: [dns_resolver]
validation:
  metrics:
    - query_sent
    - idx_pattern_count
    - avg_label_length
  success:
    query_sent: { min: 1 }
    idx_pattern_ratio: { min: 0.8 }
defaults:
  base_domain: dns-tunnel.com
  duration_sec: 180
safety:
  max_queries: 15000
  allowed_domains: [dns-tunnel.com]
```

### 8.3 Core vs Plugin Boundary

| Core (수정 필요) | Plugin (폴더 추가) |
|------------------|-------------------|
| Event Store schema | Protocol executor |
| Validation Engine framework | Threshold values |
| Runner CLI | FQDN/URL generation logic |
| Plugin Loader | MITRE tags, metadata |

---

## 9. Deployment Topology

### 9.1 Phase 1 — Local Executor

```
[Operator host]
  dsp run
    → scenarios execute locally
    → Event Store: ~/.dsp/runs/<run_id>/events.db
    → Report: ~/.dsp/runs/<run_id>/report.md
```

### 9.2 Phase 2 — Remote Executor Adapter

레거시 webshell bootstrap 패턴을 **adapter**로 격리:

```
dsp run --executor remote-webshell
  → copies executor.py to victim
  → remote append → sync back to local Event Store
```

Remote path도 **동일 Event schema**. sync 후 local Validation Engine이 판정.

### 9.3 Integration with xdr-lab-appliance

DSP는 별도 패키지. xdr-lab CLI(`aella_cli`)와 통합 시:

```
aella_cli poc run --engine dsp --scenarios dns_tunnel,dga
```

기존 `stellar_poc.sh` 호출 경로는 유지하지 않음 (legacy, 별도 maintenance).

---

## 10. Observability

| Signal | 용도 | SOT? |
|--------|------|------|
| Event Store | validation, reporting | **Yes** |
| Structured log (JSON lines) | debug, audit | No |
| Executor stdout | human progress | No |
| Metrics (Prometheus, future) | ops dashboard | No |

로그에 `run_id`, `scenario`, `event_id` correlation ID 필수.

---

## 11. Security Architecture

```
┌─────────────────────────────────────┐
│         Safety Envelope             │
│  ┌───────────────────────────────┐  │
│  │ Target Engine: CIDR check     │  │
│  ├───────────────────────────────┤  │
│  │ Manifest safety block         │  │
│  ├───────────────────────────────┤  │
│  │ Runner: dry-run mode          │  │
│  ├───────────────────────────────┤  │
│  │ Volume caps per scenario      │  │
│  └───────────────────────────────┘  │
│           Scenario Executor         │
└─────────────────────────────────────┘
```

---

## 12. Testing Architecture

**원칙:** 테스트가 사용하는 `validate()` == 프로덕션이 사용하는 `validate()`

```
tests/
├── unit/
│   ├── test_event_store.py
│   ├── test_validation_engine.py
│   └── test_plugin_loader.py
├── scenarios/
│   ├── test_dns_tunnel_validation.py  # synthetic events → validate
│   └── test_stdout_rejection.py       # 반드시 FAIL
└── integration/
    └── test_run_e2e_dry_run.py      # dry-run → events → report
```

레거시 `test_event_sot_architecture.sh`의 테스트 케이스를 Python pytest로 **동등 이식** (threshold, fail-fast, stdout rejection).

---

## 13. Versioning & Compatibility

| Artifact | Version field |
|----------|---------------|
| Event schema | `event_schema_version` in RunContext |
| Scenario manifest | `manifest.version` |
| Validation spec | `validation.version` |
| Report format | `report_format_version` |

Breaking change 시 migration script 제공. Event Store append-only이므로 old runs는 read-only 보존.

---

## 14. Related Documents

- [PROJECT_CHARTER.md](./PROJECT_CHARTER.md)
- [SCENARIO_FRAMEWORK_SPEC.md](./SCENARIO_FRAMEWORK_SPEC.md)
- [EVENT_STORE_SPEC.md](./EVENT_STORE_SPEC.md)
- [SKILL_SPEC.md](./SKILL_SPEC.md)
