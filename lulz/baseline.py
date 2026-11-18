"""Compare a complete scan with a compatible saved baseline without hiding findings."""
from __future__ import annotations

from pathlib import Path

from .models import ScanResult
from .reports import finding_key, load_report, significant_fields, validate_comparable_scope


def apply_baseline(result: ScanResult, baseline_path: str | Path) -> ScanResult:
    """Mark current findings new/unchanged/updated; leave all evidence intact.

    Both scans must be complete. This prevents an offline inventory, failed
    request or truncated analysis from silently waiving a CI finding.
    """
    previous = load_report(baseline_path)
    current = result.to_dict()
    validate_comparable_scope(previous, current)
    if not previous["complete"] or not current["complete"]:
        raise ValueError("Baseline требует двух завершённых проверок без ошибок и ограничений охвата")
    before = {finding_key(item): item for item in previous["findings"]}
    now = set()
    counts = {"new": 0, "unchanged": 0, "updated": 0}
    states = []
    for finding in result.findings:
        item = finding.to_dict()
        key = finding_key(item)
        now.add(key)
        old = before.get(key)
        state = "new" if old is None else "unchanged" if significant_fields(old) == significant_fields(item) else "updated"
        states.append((finding, state))
        counts[state] += 1
    # Mutate only after validation succeeds, retaining every finding.
    for finding, state in states:
        finding.baseline_state = state
    result.metadata["baseline"] = {
        "applied": True,
        "file": Path(baseline_path).name,
        **counts,
        "existing": counts["unchanged"] + counts["updated"],
        "changed": counts["updated"],
        "not_seen": len(before.keys() - now),
        "previous_completed_at": previous.get("completed_at", ""),
        "matching": "rule_id + location + evidence",
    }
    return result
