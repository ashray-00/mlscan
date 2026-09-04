"""Core data model: severities, findings, and scan results."""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _RANK[self.value]

_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class Category(str, Enum):
    SERIALIZATION = "serialization"       # unsafe formats / pickle payloads
    EXECUTION = "execution"               # code that runs on load
    FILE_ANOMALY = "file_anomaly"         # unexpected/mismatched files
    METADATA = "metadata"                 # config vs weights inconsistency
    PROVENANCE = "provenance"             # who published it, how trusted
    NAMING = "naming"                     # typosquatting / namespace confusion
    INTEGRITY = "integrity"               # structural corruption, offset abuse


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    location: str                          # file path or repo-relative name
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    confidence: str = "high"               # high | medium | low
    references: list[str] = field(default_factory=list)
    is_new: bool = False                   # set by baseline diff mode

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        if not self.is_new:
            d.pop("is_new", None)
        return d


@dataclass
class FileRecord:
    path: str                 # display path (repo-relative)
    size: int
    format: str = "unknown"   # classified format label
    sha256: str | None = None
    inspected: bool = False


@dataclass
class ScanTarget:
    kind: str                 # "local" | "hub"
    identifier: str           # dir path or "org/model"
    revision: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    target: ScanTarget
    findings: list[Finding] = field(default_factory=list)
    files: list[FileRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())
    finished_at: str | None = None
    risk_score: int = 0
    verdict: str = "UNKNOWN"
    scanner_version: str = "0.1.0"
    remote_metadata: dict[str, Any] = field(default_factory=dict)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scanner_version": self.scanner_version,
            "target": asdict(self.target),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "severity_counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
            "files": [asdict(f) for f in self.files],
            "errors": self.errors,
            "remote_metadata": self.remote_metadata,
        }
