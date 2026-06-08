# DNS Tunnel Storage Analysis

**Phase:** Live validation readiness  
**Status:** Analysis complete — volume profiles added  
**Audience:** Lab operators, platform engineers

---

## 1. Observed Issue

Default dry-run without explicit parameters:

```
dns_tunnel_query_sent_count = 69,906
total_events              = 279,629
events.db                 ≈ 156 MB
events.jsonl              ≈ 149 MB
Total per run             ≈ 300 MB
```

Single dry-run consumed ~300 MB disk — unexpected for routine validation.

---

## 2. Root Cause — Intended Stress Defaults

The DNS Tunnel executor simulates **2 MB payload exfiltration** in 30-byte chunks:

| Parameter | Default (pre-Phase 19) | Effect |
|-----------|------------------------|--------|
| `payload_mb` | `2.0` | 2 × 1024 × 1024 = 2,097,152 bytes |
| `chunk_size` | `30` | Fixed chunk size |
| Planned chunks | `ceil(2097152 / 30)` = **69,906** | Per target host |

Formula (`dsp/protocols/dns/tunnel.py`):

```python
plan_chunk_count(payload_mb, chunk_size) = ceil(payload_mb * 1024 * 1024 / chunk_size)
```

This is **intentional stress-test volume** — not a bug in chunk planning.

---

## 3. Event Amplification

Each chunk generates **4 Event Store rows**:

| # | Event | Source |
|---|-------|--------|
| 1 | `dns_tunnel_chunk_created` | Tunnel executor |
| 2 | `dns_tunnel_query_sent` | Tunnel executor |
| 3 | `dns_query_sent` | DNS protocol layer (`build_dns_events`, `include_created=False`) |
| 4 | `dns_response_received` | DNS protocol layer (mock response in dry-run) |

Lifecycle events per target:

- `dns_tunnel_started`
- `dns_tunnel_completed`

Global:

- `scenario_prepared`

### Event count formula (single host)

```
total_events ≈ (chunks × 4) + 3
             ≈ (69,906 × 4) + 3
             ≈ 279,627
```

Observed **279,629** matches (minor timing/extra rows).

With `max_hosts=2` and full stress payload (no `max_chunks` cap):

```
queries  ≈ 69,906 × 2 = 139,812
events   ≈ 279,629 × 2 ≈ 559,000+
storage  ≈ 600 MB+
```

---

## 4. Storage Estimates

Measured and calculated (~550 bytes average per event row including SQLite overhead):

| Profile | Chunks | Queries | Events | events.db | events.jsonl | Total |
|---------|--------|---------|--------|-----------|--------------|-------|
| **demo** | 5 | 5 | ~23 | <50 KB | <50 KB | <100 KB |
| **standard** | 100 | 100 | ~403 | ~264 KB | ~212 KB | **~500 KB** |
| **stress** (1 host) | 69,906 | 69,906 | ~279,629 | ~156 MB | ~149 MB | **~300 MB** |
| **stress** (2 hosts) | 139,812 | 139,812 | ~559,000 | ~300+ MB | ~300+ MB | **~600 MB** |

Post-correction dry-run default (`volume_profile=standard`): **~500 KB per run**.

---

## 5. Dry-Run vs Live Behavior

| Aspect | Dry-run | Live |
|--------|---------|------|
| DNS client mode | `mock` (instant responses) | `live` (UDP/53 to target) |
| Event generation | Same per-chunk event model | Same |
| Network I/O | None | Real DNS queries |
| Duration (stress) | Seconds (CPU/IO bound) | Minutes (network bound) |
| Storage | Same event count for same params | Same |

Dry-run does **not** reduce event volume — only eliminates network latency.

---

## 6. Is 69,906 Queries Required?

**No — for normal validation and demos.**

| Use case | Required queries | Rationale |
|----------|------------------|-----------|
| S2 validation minimum | **≥ 1** | `validation_profile.success.dns_tunnel_query_sent_count.min: 1` |
| Lab S3 manual validation | **~100** | Matches `LAB_VALIDATION_PROCEDURE.md` recommendation |
| Customer demo | **5–20** | Visible idx-pattern traffic without storage risk |
| NDR stress / soak test | **69,906+** | Full 2 MB exfil simulation |

69,906 queries is **stress-test volume**, not operational default.

---

## 7. Volume Profiles (Phase 19)

Added `dsp/protocols/dns/volume_profiles.py`:

| Profile | `max_chunks` | `payload_mb` | `max_hosts` | Use case |
|---------|--------------|--------------|-------------|----------|
| `demo` | 5 | 0.0001 | 1 | Quick smoke, CI-adjacent demos |
| `standard` | 100 | 0.01 | 1 | **Default** — lab validation, live prep |
| `stress` | unlimited (2 MB) | 2.0 | 2 | Full exfil simulation, soak tests |

### Default behavior

When no explicit volume parameters are passed, executor applies **`standard`** profile (dry-run and live).

### Explicit override

```bash
# Demo volume
dsp run --scenarios dns_tunnel --dry-run \
  --scenario-params '{"dns_tunnel": {"volume_profile": "demo"}}'

# Full stress test (previous default behavior)
dsp run --scenarios dns_tunnel --dry-run \
  --scenario-params '{"dns_tunnel": {"volume_profile": "stress"}}'

# Fine-grained control (existing)
dsp run --scenarios dns_tunnel \
  --scenario-params '{"dns_tunnel": {"max_chunks": 100, "targets": ["10.10.10.20"]}}'
```

Explicit `payload_mb`, `max_chunks`, `chunk_size`, `max_hosts`, or `volume_profile` override defaults.

---

## 8. Operational Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Disk exhaustion (stress default) | **High** | Use `standard` or `demo` profile; cap `max_chunks` |
| Long dry-run duration at stress | Medium | Profile defaults now `standard` (100 chunks) |
| SQLite DB >100 MB per run | Medium | Avoid `stress` unless intentional |
| JSONL export doubles storage | Medium | Archive/delete old runs; set `DSP_RUNS_DIR` on large volume |
| Multi-host amplification | High | `standard`/`demo` use `max_hosts: 1` |
| `safety.max_events: 500000` | Low at standard | Stress 2-host approaches limit |

---

## 9. Recommendations

| Scenario | Command profile |
|----------|-----------------|
| Live validation prep | Default (standard) — no extra params |
| Customer demo | `volume_profile: demo` |
| Stellar S3 lab battery | `max_chunks: 100` (standard default) |
| NDR soak / performance | `volume_profile: stress` |
| CI / E2E tests | Explicit tiny params (existing test fixtures) |

---

## 10. Related Files

| File | Role |
|------|------|
| `scenarios/dns_tunnel/executor.py` | Chunk loop, event generation |
| `scenarios/dns_tunnel/manifest.yaml` | Validation thresholds, safety limits |
| `dsp/protocols/dns/tunnel.py` | Chunk planning math |
| `dsp/protocols/dns/events.py` | Per-query protocol events |
| `dsp/protocols/dns/volume_profiles.py` | Named operational profiles |
| `tests/protocols/dns/test_volume_profiles.py` | Profile regression tests |
