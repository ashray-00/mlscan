"""Fail if any rule_id in mlscan/ is missing from docs/RULES.md."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CODE = ROOT / "mlscan"
DOC = ROOT / "docs" / "RULES.md"
RULE_RE = re.compile(r'["\'](MLSC-[A-Z0-9]+-\d+)["\']')


def test_every_rule_id_is_documented():
    assert DOC.is_file(), f"missing {DOC}"
    doc = DOC.read_text(encoding="utf-8")
    code_ids: set[str] = set()
    for path in CODE.rglob("*.py"):
        code_ids.update(RULE_RE.findall(path.read_text(encoding="utf-8")))
    missing = sorted(rid for rid in code_ids if rid not in doc)
    assert not missing, f"rule IDs missing from docs/RULES.md: {missing}"
