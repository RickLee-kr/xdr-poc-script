# DSP Execution Guide

**문서 버전:** 1.0.0  
**상태:** Live Validation 준비 — 조사 기반 실행 가이드  
**대상:** Lab operator, SE, validation engineer

---

## 1. 개요

Detection Scenario Platform(DSP)은 Python 패키지 `dsp`로 배포되며, 콘솔 진입점 `dsp`를 통해 시나리오를 실행한다.

**프로젝트 루트:** `detection-scenario-platform/` (workspace 내 `xdr-lab-appliance/detection-scenario-platform/`)

현재 증상 `Command 'dsp' not found`는 **패키지 미설치** 또는 **가상환경 미활성화**가 원인이다. `pyproject.toml`에 CLI entry point는 **정상 등록**되어 있다.

---

## 2. 패키징 요약

| 항목 | 실제 값 |
|------|---------|
| 패키지 이름 (PyPI/project) | `dsp` |
| 실행 파일 이름 | `dsp` |
| Entry point | `[project.scripts]` → `dsp = "dsp.runner.cli:main"` |
| 빌드 백엔드 | hatchling |
| Python 요구 버전 | `>=3.11` |
| 런타임 의존성 | `pyyaml>=6.0` |
| 개발 의존성 | `pytest>=8.0` (optional `[dev]`) |
| `setup.py` | **없음** (DSP 디렉터리 내) |
| `setup.cfg` | **없음** |
| `requirements*.txt` | **없음** — `pyproject.toml`이 SOT |

---

## 3. Fresh Install

### 3.1 사전 조건

- Python 3.11 이상 (`python3 --version`)
- `pip` (venv와 함께 제공)
- Git clone 또는 workspace checkout 완료

### 3.2 가상환경 생성 및 의존성 설치

```bash
cd /path/to/xdr-lab-appliance/detection-scenario-platform

python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -e ".[dev]"
```

**Editable install 확인:**

```bash
pip show dsp
# Editable project location: .../detection-scenario-platform
```

### 3.3 CLI 사용 가능 여부 확인

```bash
# venv 활성화 후
which dsp
# .../detection-scenario-platform/.venv/bin/dsp

dsp --version
# dsp 1.0.0

dsp plugins list
# 12 scenarios, 모두 active
```

> **주의:** venv를 활성화하지 않으면 `dsp`가 PATH에 없다.  
> 활성화 없이 실행하려면 `.venv/bin/dsp` 전체 경로를 사용한다.

---

## 4. 지원 CLI 명령

| 명령 | 설명 |
|------|------|
| `dsp --version` | 버전 출력 |
| `dsp run --scenarios <ids>` | 시나리오 실행 (필수: `--scenarios`, **복수형**) |
| `dsp plugins list` | 등록된 플러그인 목록 |
| `dsp report --run-id <id>` | 기존 run artifact에서 report 재생성 |

### 4.1 `dsp run` 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--scenarios` | (필수) | 쉼표로 구분된 scenario ID (예: `dns_tunnel,dga`) |
| `--dry-run` | off | 플래그. 지정 시 네트워크 없이 mock 실행 |
| `--target-net` | `10.10.10.0/24` | 대상 CIDR |
| `--confirm-detection` | off | S2 이후 S3 manual evidence templates (exit code에 영향 없음) |
| `--detection-provider` | `stellar` | detection provider (HTTP/mock automation 시) |
| `--stellar-client` | `manual` | `manual` (기본), `mock` (CI/demo), `http` (experimental) |

### 4.2 자주 발생하는 오류

| 입력 | 문제 | 올바른 형태 |
|------|------|-------------|
| `dsp run --scenario dns_tunnel` | `--scenario` 플래그 **미존재** | `dsp run --scenarios dns_tunnel` |
| `dsp run ...` (venv 미활성) | `Command 'dsp' not found` | `source .venv/bin/activate` 또는 `.venv/bin/dsp run ...` |
| `--dry-run false` | CLI는 boolean **플래그**만 지원 | live 실행: `--dry-run` **생략** |
| `--scenario-params '...'` | CLI에 **미노출** (RunManager API만 지원) | 기본 manifest defaults 사용; 커스텀 params는 Python API 필요 |

---

## 5. 실행 방법 (Module vs CLI)

공식 지원 방법은 [KNOWN_EXECUTION_MODES.md](./KNOWN_EXECUTION_MODES.md) 참조.

**권장 (운영):**

```bash
source .venv/bin/activate
dsp run --scenarios dns_tunnel --dry-run
```

**venv 경로 직접 지정 (CI/스크립트):**

```bash
/path/to/detection-scenario-platform/.venv/bin/dsp run --scenarios dummy --dry-run
```

**모듈 직접 실행 (대안):**

```bash
.venv/bin/python -m dsp.runner.cli run --scenarios dummy --dry-run
```

**지원되지 않음:**

```bash
python -m dsp   # dsp/__main__.py 없음 → No module named dsp.__main__
```

---

## 6. Run Artifacts

기본 run 디렉터리: `~/.dsp/runs/<run_id>/`

환경변수 `DSP_RUNS_DIR`로 override 가능.

| Artifact | 설명 |
|----------|------|
| `events.db` | SQLite Event Store (SOT) |
| `run.json` | Run 메타데이터 |
| `manifest.snapshot.<scenario>.json` | 시나리오별 resolved manifest |
| `validation.json` | ValidationResult[] |
| `report.md` / `report.json` | 리포트 |
| `events.jsonl` | 이벤트 export |
| `evidence/<run_id>/manual/` | `--confirm-detection` 시 manual S3 evidence (기본) |
| `evidence/<run_id>/stellar/` | `--confirm-detection --stellar-client mock\|http` 시 API evidence |

See also:

- [RUN_METADATA_CONSISTENCY_REVIEW.md](./RUN_METADATA_CONSISTENCY_REVIEW.md)
- [DNS_TUNNEL_STORAGE_ANALYSIS.md](./DNS_TUNNEL_STORAGE_ANALYSIS.md)

---

## 7. 시나리오별 실행 예시

모든 시나리오 ID는 `dsp plugins list`로 확인한다. 현재 **12개 active**:

### 7.1 Architecture / Protocol verification (dry-run 권장)

```bash
# Phase 1A skeleton
dsp run --scenarios dummy --dry-run

# Phase 1B DNS mock
dsp run --scenarios dns_dummy --dry-run

# Phase 1C DNS transport mock
dsp run --scenarios dns_transport_dummy --dry-run
```

### 7.2 MVP / Live traffic scenarios

```bash
# DNS Tunnel (UDP/53) — dry-run ~50s 소요 가능
dsp run --scenarios dns_tunnel --dry-run
dsp run --scenarios dns_tunnel --target-net 10.10.10.0/24

# DGA
dsp run --scenarios dga --dry-run
dsp run --scenarios dga --target-net 10.10.10.0/24

# HTTP follow-up
dsp run --scenarios http_followup --dry-run
dsp run --scenarios http_followup --target-net 10.10.10.0/24

# SSH failure
dsp run --scenarios ssh_failure --dry-run
dsp run --scenarios ssh_failure --target-net 10.10.10.0/24

# SQL injection
dsp run --scenarios sql_injection --dry-run
dsp run --scenarios sql_injection --target-net 10.10.10.0/24
```

### 7.3 Phase 16+ extended scenarios

```bash
dsp run --scenarios kerberos_failure --dry-run
dsp run --scenarios ldap_enumeration --dry-run
dsp run --scenarios port_sweep --dry-run
dsp run --scenarios smb_login_failure --dry-run
```

### 7.4 Multi-scenario battery

```bash
dsp run --scenarios dns_tunnel,dga,http_followup --dry-run
```

### 7.5 S3 detection confirmation (manual — default)

```bash
# Manual S3 evidence templates (no Stellar API required)
dsp run --scenarios dns_tunnel --confirm-detection

# Operator workflow after run:
# 1. Open Stellar UI
# 2. Search by time window / source IP / destination IP
# 3. Capture alert ID and screenshot
# 4. Complete evidence/<run_id>/manual/correlation_notes.md
```

### 7.6 Experimental Stellar HTTP API (optional)

> API token required. See `docs/experimental/STELLAR_HTTP_API_MODE.md`.

```bash
export DSP_STELLAR_BASE_URL=https://stellar.lab.example
export DSP_STELLAR_API_TOKEN=<token>
dsp run --scenarios dns_tunnel \
  --target-net 10.10.10.0/24 \
  --confirm-detection \
  --detection-provider stellar \
  --stellar-client http
```

### 7.7 Report 재생성

```bash
dsp report --run-id 20260605_1dd098
```

---

## 8. 테스트 실행

```bash
cd detection-scenario-platform
source .venv/bin/activate
pytest -v
# 현재: 278 passed
```

---

## 9. 문서 vs 실제 불일치 (조사 결과)

| 문서 | 불일치 내용 |
|------|-------------|
| `README.md` 헤더 | "Phase 0.6 — 구현 코드 없음" → **구현 완료 상태와 불일치** |
| `LAB_VALIDATION_PROCEDURE.md` §3.2 | `--dry-run false`, `--scenario-params` → **CLI 미지원** |
| `PLUGIN_DISCOVERY_SPEC.md` | `DSP_SCENARIOS_DIR` env → **loader.py 미구현** (hardcoded `scenarios/`) |

Live validation 시 본 문서(`docs/runtime/`)를 **실행 SOT**로 사용한다.

---

## 10. 관련 문서

- [ENVIRONMENT_VALIDATION.md](./ENVIRONMENT_VALIDATION.md)
- [LIVE_VALIDATION_CHECKLIST.md](./LIVE_VALIDATION_CHECKLIST.md)
- [KNOWN_EXECUTION_MODES.md](./KNOWN_EXECUTION_MODES.md)
- [../detection/PHASE_12_PRODUCTION_HARDENING.md](../detection/PHASE_12_PRODUCTION_HARDENING.md) — Stellar tuning
- [../../LAB_VALIDATION_PROCEDURE.md](../../LAB_VALIDATION_PROCEDURE.md) — S3 수동 검증 (CLI 플래그 주의)
