# DSP Environment Validation

**문서 버전:** 1.0.0  
**상태:** Live Validation 사전 환경 점검  
**조사 일자:** 2026-06-05

---

## 1. Python Runtime

| 요구사항 | 값 | 검증 방법 |
|----------|-----|-----------|
| Python 버전 | **≥ 3.11** | `python3 --version` |
| 권장 | 3.11 또는 3.12 | lab host에서 확인됨: 3.12.3 |
| venv | 권장 | `python3 -m venv .venv` |

---

## 2. Required Packages

`pyproject.toml` 기준. 별도 `requirements.txt` 없음.

### 2.1 Runtime

| Package | Version | 용도 |
|---------|---------|------|
| `pyyaml` | `>=6.0` | manifest.yaml 파싱 |
| `dsp` (editable) | `1.0.0` | 본 패키지 |

### 2.2 Development / CI

| Package | Version | 용도 |
|---------|---------|------|
| `pytest` | `>=8.0` | 테스트 (`pip install -e ".[dev]"`) |

### 2.3 설치 검증

```bash
cd detection-scenario-platform
pip install -e ".[dev]"
pip show dsp pyyaml pytest
```

**표준 라이브러리만 사용하는 영역:** `sqlite3`, `argparse`, `json`, `uuid`, `pathlib`, `urllib` (Stellar HTTP client) — 별도 pip 의존성 없음.

---

## 3. Environment Variables

### 3.1 DSP Core

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DSP_RUNS_DIR` | No | `~/.dsp/runs` | Run artifact 및 evidence 루트 |
| `DSP_SCENARIOS_DIR` | No | *(hardcoded)* `detection-scenario-platform/scenarios/` | **스펙 문서에만 존재 — 코드 미구현** |
| `DSP_INVENTORY` | No | — | Target inventory path ([TARGET_PROVIDER_SPEC.md](../../TARGET_PROVIDER_SPEC.md)) — deployment 통합 시 |

### 3.2 Stellar HTTP Client (`--stellar-client http`) — Experimental

**Not required for normal DSP operation.** Only when explicitly using live Stellar API automation.

#### Required

| Variable | Description |
|----------|-------------|
| `DSP_STELLAR_BASE_URL` | Stellar API base URL (예: `https://stellar.lab.example`) |
| `DSP_STELLAR_API_TOKEN` | Bearer token |

#### Optional (defaults from `stellar_config.py`)

| Variable | Default |
|----------|---------|
| `DSP_STELLAR_VERIFY_TLS` | `true` |
| `DSP_STELLAR_TIMEOUT_SECONDS` | `30` |
| `DSP_STELLAR_PAGE_SIZE` | `100` |
| `DSP_STELLAR_REQUEST_DELAY_SECONDS` | `0.0` |
| `DSP_STELLAR_MAX_REQUESTS_PER_RUN` | `200` |
| `DSP_STELLAR_MAX_RETRIES` | `2` |
| `DSP_STELLAR_RETRY_BACKOFF_SECONDS` | `0.05` |
| `DSP_STELLAR_MAX_ALERTS` | `500` |
| `DSP_STELLAR_MAX_ANALYTICS` | `500` |
| `DSP_STELLAR_MAX_ENTITIES` | `500` |
| `DSP_STELLAR_MAX_TIMELINE` | `1000` |

### 3.3 Stellar 설정 검증

```bash
# Manual mode (default) — no Stellar env required
dsp run --scenarios dummy --dry-run --confirm-detection

# Mock mode (CI/demo)
dsp run --scenarios dummy --dry-run --confirm-detection --stellar-client mock

# HTTP mode (experimental) — env required
export DSP_STELLAR_BASE_URL=https://stellar.lab.example
export DSP_STELLAR_API_TOKEN=<token>
dsp run --scenarios dns_tunnel --confirm-detection --stellar-client http --dry-run
```

---

## 4. Stellar Settings (Lab)

| Component | Requirement |
|-----------|-------------|
| Stellar Cyber tenant | NDR sensor licensed; analytics processing enabled |
| Authentication | API token with alert/analytics read access |
| Time sync | Runner host ↔ Stellar UTC aligned (correlation) |
| Baseline traffic | Runner source IP가 Stellar entity에 표시되는지 pre-flight 확인 |

자세한 API contract: [../detection/STELLAR_API_CONTRACT.md](../detection/STELLAR_API_CONTRACT.md)

---

## 5. Network Requirements

### 5.1 Lab Topology (Minimum)

| Component | Requirement |
|-----------|-------------|
| DSP runner host | Egress to `target_net`; Stellar API HTTPS (S3 only) |
| Target network | Default `10.10.10.0/24` or documented lab CIDR |
| Traffic visibility | NDR/SPAN/TAP — runner→target path monitored |

### 5.2 Protocol / Port Matrix

| Scenario | Protocol | Ports | Notes |
|----------|----------|-------|-------|
| `dns_tunnel`, `dga`, `dns_*` | UDP DNS | 53 | Resolver reachable |
| `http_followup`, `sql_injection` | HTTP/HTTPS | 80, 443, 8080, 8000, 8443 | Web server alive |
| `ssh_failure` | SSH | 22 | Linux host |
| `kerberos_failure` | Kerberos | 88 | Domain controller optional |
| `ldap_enumeration` | LDAP | 389, 636 | Directory reachable |
| `port_sweep` | TCP | 다수 common ports | Controlled connect attempts |
| `smb_login_failure` | SMB | 445 | Windows/SMB host |

### 5.3 Firewall Rules

- Allow egress from runner to targets per scenario
- DNS: internal resolver or lab DNS forwarding (`xdr.ooo` for DGA)
- Stellar API: HTTPS egress from runner (S3 confirmation)

### 5.4 Dry-run vs Live

| Mode | Network | Stellar |
|------|---------|---------|
| `--dry-run` | **No real traffic** (mock/local events) | Optional mock S3 |
| Live (flag omitted) | Real protocol traffic to `target_net` | Optional live S3 |

---

## 6. Filesystem Requirements

| Path | Permission | Purpose |
|------|------------|---------|
| `~/.dsp/runs/` or `DSP_RUNS_DIR` | **Read/Write/Execute** | Run artifacts, SQLite DB |
| `DSP_RUNS_DIR/<run_id>/events.db` | Write | Event Store (SQLite, per-run) |
| `DSP_RUNS_DIR/<run_id>/evidence/` | Write | S3 detection evidence packs |
| `detection-scenario-platform/scenarios/` | Read | Plugin manifests + scenario code |
| Temp / SQLite journal | Write | Same directory as `events.db` |

### 6.1 Filesystem 검증

```bash
# Writable runs dir
export DSP_RUNS_DIR=/path/to/lab-evidence/runs
mkdir -p "$DSP_RUNS_DIR"
touch "$DSP_RUNS_DIR/.write_test" && rm "$DSP_RUNS_DIR/.write_test"

# Sample run
dsp run --scenarios dummy --dry-run
ls -la "$DSP_RUNS_DIR"/$(ls -t "$DSP_RUNS_DIR" | head -1)/
```

### 6.2 Disk Space

- Per-run: ~40–100 KB (dummy) to several MB (high-volume scenarios)
- SQLite DB grows with event count
- S3 evidence: depends on Stellar response size (limits via `DSP_STELLAR_MAX_*`)

---

## 7. Pre-Flight Checklist (Quick)

```bash
python3 --version          # >= 3.11
pip show dsp               # installed editable
dsp --version              # dsp 1.0.0
dsp plugins list           # 12 active scenarios
pytest -q                  # 278 passed
test -w "$DSP_RUNS_DIR"    # or ~/.dsp/runs writable
```

Live validation 추가:

```bash
ping -c1 <target_host>     # reachability
curl -sk "$DSP_STELLAR_BASE_URL/..."  # Stellar API (if S3)
```

---

## 8. Related Documents

- [EXECUTION_GUIDE.md](./EXECUTION_GUIDE.md)
- [LIVE_VALIDATION_CHECKLIST.md](./LIVE_VALIDATION_CHECKLIST.md)
- [../../LAB_VALIDATION_PROCEDURE.md](../../LAB_VALIDATION_PROCEDURE.md)
