"""Baseline / diff mode for adoptable gates on repos with known findings.

Suppress findings whose `(rule_id, target, sha256-of-target-file)` triple is
unchanged since a previous JSON report. New findings are marked `is_new` so
every reporter can surface them clearly. Without this, teams cannot turn the
gate on against an existing corpus of accepted risks.
"""
from __future__ import annotations

import json
from pathlib import Path

from .findings import Finding, ScanResult


def _file_hashes(result: ScanResult) -> dict[str, str]:
    return {f.path: f.sha256 for f in result.files if f.sha256}


def _triple(f: Finding, hashes: dict[str, str]) -> tuple[str, str, str]:
    # location may be "file!member" — hash the outer file when possible
    outer = f.location.split("!", 1)[0]
    return (f.rule_id, f.location, hashes.get(outer) or hashes.get(f.location) or "")


def baseline_keyset(data: dict) -> set[tuple[str, str, str]]:
    hashes = {f["path"]: f.get("sha256") or "" for f in data.get("files", [])}
    keys: set[tuple[str, str, str]] = set()
    for f in data.get("findings", []):
        loc = f.get("location") or ""
        outer = loc.split("!", 1)[0]
        keys.add((f.get("rule_id") or "", loc, hashes.get(outer) or hashes.get(loc) or ""))
    return keys


def apply_baseline(result: ScanResult, baseline_path: Path) -> None:
    """Drop findings present in the baseline; mark the rest as new."""
    data = json.loads(baseline_path.read_text(encoding="utf-8"))
    prior = baseline_keyset(data)
    hashes = _file_hashes(result)
    kept: list[Finding] = []
    for f in result.findings:
        if _triple(f, hashes) in prior:
            continue
        f.is_new = True
        kept.append(f)
    result.findings = kept
    result.remote_metadata["baseline"] = str(baseline_path)
    result.remote_metadata["baseline_suppressed"] = True


def write_baseline(result: ScanResult, path: Path) -> None:
    path.write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")
