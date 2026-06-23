"""HTTP User-Agent pools — Stellar suspected malicious UA documents."""

from __future__ import annotations

import csv
import random
import re
from functools import lru_cache
from pathlib import Path

_UA_NORMAL = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_UA_CSV_DIR = _REPO_ROOT / "user-agent-csv"
_UA_CSV_GLOB = "Suspected Malicious User Agent Documents*.csv"

_RE_SCANNER = re.compile(
    r"TelemetryCollector|ReconEngine|ThreatHunter|DiscoveryProbe|"
    r"SecurityAssessment|AuditScanner|EnumerationFramework|AssetProfiler|"
    r"NetworkSurvey|VulnerabilitySweep|InternalAudit",
    re.IGNORECASE,
)
_RE_SQLI = re.compile(
    r"OR 1=1|SLEEP\(|pg_sleep|waitfor delay|convert\(int|'='|2\+701|\$\{jndi:",
    re.IGNORECASE,
)
_RE_ENC = re.compile(r"%00|%0d|%0a|%2f|%252e|\.\./|/etc/passwd|%%%%|@@@@|<<<<")
_RE_CMD = re.compile(r";id|;whoami|&&hostname|\|cat ")


@lru_cache(maxsize=1)
def _load_malicious_user_agents() -> tuple[str, ...]:
    csv_files = sorted(_UA_CSV_DIR.glob(_UA_CSV_GLOB))
    if not csv_files:
        raise FileNotFoundError(f"No user agent CSV found under {_UA_CSV_DIR}")
    uas: set[str] = set()
    for csv_path in csv_files:
        with csv_path.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                ua = (row.get("User Agent") or "").strip()
                if ua:
                    uas.add(ua)
    if not uas:
        raise ValueError(f"No user agents loaded from {_UA_CSV_DIR}")
    return tuple(sorted(uas))


def malicious_user_agents() -> tuple[str, ...]:
    """Unique suspected malicious User-Agent strings from user-agent-csv/."""
    return _load_malicious_user_agents()


def pick_normal_user_agent() -> str:
    return random.choice(_UA_NORMAL)


def pick_abnormal_user_agent() -> str:
    return random.choice(_load_malicious_user_agents())


def pick_rare_user_agent() -> str:
    return pick_abnormal_user_agent()


def pick_user_agent() -> str:
    """10% normal browser UA, 90% Stellar suspected malicious UA."""
    if random.randrange(100) < 10:
        return pick_normal_user_agent()
    return pick_abnormal_user_agent()


def is_scanner_user_agent(ua: str) -> bool:
    return bool(_RE_SCANNER.search(ua))


def is_payload_only_user_agent(ua: str) -> bool:
    """True when UA is a pure attack string with no scanner token."""
    if is_scanner_user_agent(ua):
        return False
    if is_normal_user_agent(ua):
        return False
    return ua in _load_malicious_user_agents()


def pick_url_scan_user_agent() -> str:
    """Pick a suspected malicious UA from Stellar documents."""
    return pick_abnormal_user_agent()


def is_normal_user_agent(ua: str) -> bool:
    return any(marker in ua for marker in ("Chrome/120.0.0.0", "Version/17.0 Safari"))


def is_abnormal_user_agent(ua: str) -> bool:
    """True for suspected malicious UA used to trigger User-Agent anomaly detection."""
    return not is_normal_user_agent(ua)


def attach_followup_user_agents(
    plans: list,
    *,
    abnormal_ratio: float = 0.10,
) -> tuple[list, dict[str, int | float]]:
    """
    Assign User-Agent per planned request — abnormal scanner UA vs normal browser UA.

    Attack paths/queries stay on every request; only UA mix changes detection volume.
    """
    from dsp.protocols.http.urls import PlannedHttpRequest

    total = len(plans)
    if total == 0:
        return [], {
            "abnormal_user_agents_planned": 0,
            "normal_user_agents_planned": 0,
            "abnormal_ua_ratio": abnormal_ratio,
        }

    ratio = max(0.0, min(1.0, abnormal_ratio))
    abnormal_count = max(0, min(total, round(total * ratio)))
    abnormal_indices = set(random.sample(range(total), abnormal_count))

    enriched: list[PlannedHttpRequest] = []
    for idx, plan in enumerate(plans):
        ua = pick_url_scan_user_agent() if idx in abnormal_indices else pick_normal_user_agent()
        enriched.append(
            PlannedHttpRequest(
                host=plan.host,
                port=plan.port,
                path=plan.path,
                query=plan.query,
                method=plan.method,
                headers={"User-Agent": ua},
            )
        )

    return enriched, {
        "abnormal_user_agents_planned": abnormal_count,
        "normal_user_agents_planned": total - abnormal_count,
        "abnormal_ua_ratio": ratio,
    }


def classify_user_agent(ua: str) -> str:
    """Categorize UA for evidence reporting."""
    if is_normal_user_agent(ua):
        return "normal"
    if _RE_SCANNER.search(ua):
        if _RE_SQLI.search(ua) or _RE_ENC.search(ua) or _RE_CMD.search(ua):
            return "rare_with_payload"
        return "rare"
    if _RE_SQLI.search(ua):
        return "payload_sqli"
    if _RE_ENC.search(ua):
        return "payload_lfi"
    if _RE_CMD.search(ua):
        return "payload_cmd"
    return "payload_other"
