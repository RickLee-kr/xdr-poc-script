# DSP Live Validation Checklist

**문서 버전:** 1.0.0  
**상태:** Live Validation 진입 전 점검 목록  
**Feature freeze:** Phase 17 완료 — 기능 개발 중단, 검증만 수행

---

## 사용 방법

각 항목을 순서대로 확인하고 `[ ]` → `[x]`로 표시한다.  
실패 항목은 **중단 사유**를 기록하고 [EXECUTION_GUIDE.md](./EXECUTION_GUIDE.md) 또는 [ENVIRONMENT_VALIDATION.md](./ENVIRONMENT_VALIDATION.md)를 참조한다.

**Operator / Date / Stellar version / DSP version:** ___________________

---

## A. Installation & CLI

- [ ] **프로젝트 설치됨** — `pip show dsp` → `Editable project location: .../detection-scenario-platform`
- [ ] **가상환경 활성화** — `which python` → `.venv/bin/python` (또는 전체 경로 `.venv/bin/dsp` 사용 문서화)
- [ ] **CLI available** — `dsp --version` → `dsp 1.0.0` (또는 `.venv/bin/dsp --version`)
- [ ] **플러그인 로드** — `dsp plugins list` → 12 scenarios, status `active`
- [ ] **올바른 run syntax** — `dsp run --scenarios dummy --dry-run` (**`--scenarios` 복수형**)

---

## B. Test Suite

- [ ] **Tests pass** — `pytest -q` → **278 passed**
- [ ] **Path equality** (optional spot-check) — `pytest tests/validation/test_path_equality.py -v`

---

## C. Event Store & Artifacts

- [ ] **Event Store writable** — run 후 `events.db` 생성 확인
- [ ] **Run directory** — `DSP_RUNS_DIR` 또는 `~/.dsp/runs/<run_id>/` 존재
- [ ] **Core artifacts present** — `run.json`, `validation.json`, `events.jsonl`, `manifest.snapshot.*.json`
- [ ] **S2 validation** — `validation.json` → `decision: success` (live run 목표)

---

## D. Reporting

- [ ] **Report generation works** — run 완료 후 `report.md`, `report.json` 존재
- [ ] **Report regenerate** — `dsp report --run-id <run_id>` 성공

---

## E. Detection Evidence (S3)

- [ ] **Manual S3 evidence path writable** — `--confirm-detection` run 시 `evidence/<run_id>/manual/` 생성
- [ ] **Manual S3 smoke test** — `dsp run --scenarios dummy --dry-run --confirm-detection` exit 0; `s3_result_manual.json` 존재
- [ ] **Stellar UI review completed** — `correlation_notes.md` 작성, alert ID / screenshot 수집
- [ ] *(Optional, experimental)* **Stellar HTTP env vars** — `--stellar-client http` 사용 시만 `DSP_STELLAR_BASE_URL`, `DSP_STELLAR_API_TOKEN`

---

## F. Network & Targets (Live Traffic)

- [ ] **Target net configured** — `--target-net` matches lab CIDR (default `10.10.10.0/24`)
- [ ] **Target hosts reachable** — ping/curl/ssh per scenario
- [ ] **NDR visibility** — Stellar에서 runner source IP baseline traffic 확인
- [ ] **Dry-run omitted for live** — live validation: **`--dry-run` 플래그 생략**

---

## G. MVP Scenario Battery (Sequential)

각 run_id 기록. S2 success 필수. S3는 Stellar에서 별도 확인.

| # | Scenario | Run ID | S2 | S3 | Notes |
|---|----------|--------|----|----|-------|
| 1 | `dns_tunnel` | | | | |
| 2 | `dga` | | | | |
| 3 | `http_followup` | | | | |
| 4 | `ssh_failure` | | | | |
| 5 | `sql_injection` | | | | |

Extended (Phase 16+):

| # | Scenario | Run ID | S2 | S3 | Notes |
|---|----------|--------|----|----|-------|
| 6 | `kerberos_failure` | | | | |
| 7 | `ldap_enumeration` | | | | |
| 8 | `port_sweep` | | | | |
| 9 | `smb_login_failure` | | | | |

---

## H. Exit Code Policy

| Exit Code | Meaning |
|-----------|---------|
| `0` | All scenarios S2 `success` |
| `1` | S2 `failed` or `partial` |
| `2` | S2 `code_failure` or detection config error |
| `3` | No results / all skipped / config error |

> S3 (`--confirm-detection`) 결과는 **exit code에 영향 없음**.

---

## I. Evidence Archive

- [ ] Run directories archived under `lab-evidence/YYYY-MM-DD_mvp_validation/<run_id>/dsp/`
- [ ] Stellar screenshots/exports under `.../stellar/`
- [ ] `notes.md` with S3 confirmed Y/N, alert IDs

---

## J. Known Blockers (Investigation 2026-06-05)

| Blocker | Impact | Workaround |
|---------|--------|------------|
| `dsp` not in PATH | Operator cannot run bare `dsp` | `source .venv/bin/activate` or `.venv/bin/dsp` |
| `--scenario` typo | argparse error | Use `--scenarios` |
| `python -m dsp` fails | No `__main__.py` | Use `dsp` or `python -m dsp.runner.cli` |
| `--scenario-params` CLI missing | Cannot tune volume from CLI | Use manifest defaults; Python API for custom params |
| `LAB_VALIDATION_PROCEDURE.md` outdated flags | Operator confusion | Use `docs/runtime/EXECUTION_GUIDE.md` |

---

## Sign-off

| Role | Name | Date | Result |
|------|------|------|--------|
| Operator | | | |
| Reviewer | | | |

**Live Validation GO / NO-GO:** ___________
