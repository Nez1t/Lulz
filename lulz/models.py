"""Shared, serializable report types. No network or filesystem side effects."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json


SEVERITIES = ("critical", "high", "medium", "low", "info")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    evidence: str
    remediation: str
    location: str = ""
    confidence: str = "medium"
    status: str = "review"
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    baseline_state: str = ""

    @property
    def fingerprint(self) -> str:
        key = json.dumps([self.rule_id, self.location, self.evidence], ensure_ascii=False)
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> dict:
        result = asdict(self)
        result["fingerprint"] = self.fingerprint
        return result


@dataclass
class ScanResult:
    kind: str
    target: str
    started_at: str = field(default_factory=utc_now)
    completed_at: str = ""
    modules: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    checks: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def finish(self) -> "ScanResult":
        self.completed_at = utc_now()
        unique = {finding.fingerprint: finding for finding in self.findings}
        self.findings = sorted(unique.values(), key=lambda f: (
            SEVERITIES.index(f.severity) if f.severity in SEVERITIES else 4,
            f.rule_id, f.location,
        ))
        return self

    def to_dict(self) -> dict:
        from . import __version__
        result = asdict(self)
        result["findings"] = [finding.to_dict() for finding in self.findings]
        result["schema_version"] = "1.0"
        result["tool"] = {"name": "Lulz", "version": __version__}
        result["summary"] = {severity: sum(f.severity == severity for f in self.findings)
                             for severity in SEVERITIES}
        result["complete"] = not self.errors and not self.metadata.get("incomplete", False)
        return result
