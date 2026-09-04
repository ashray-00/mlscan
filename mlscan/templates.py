"""Chat-template scanning for JSON configs and `.jinja` files.

HF transformers usually store `chat_template` in `tokenizer_config.json`.
Jinja escapes there are RCE on the serving host at inference time.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from .findings import Category, Finding, Severity

ANALYZER = "templates"

JINJA_EXEC_HINT = re.compile(
    r"(__class__|__mro__|__subclasses__|__globals__|__builtins__|__init__|"
    r"__import__|__reduce__|lipsum|cycler|joiner|namespace|self\.__|"
    r"config\.items|request\.application|os\.popen|attr\s*\()")
JINJA_ANY = re.compile(r"\{\{|\{%")

TEMPLATE_FILES = {
    "tokenizer_config.json", "chat_template.json", "chat_template.jinja",
    "processor_config.json", "generation_config.json", "config.json",
}
TEMPLATE_KEYS = ("chat_template", "chat_templates", "template",
                 "default_chat_template", "prompt_template")


def _walk_strings(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(obj, str):
        yield path or "<root>", obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")


def analyze_templates(root: Path, files: list[Path]) -> list[Finding]:
    out: list[Finding] = []
    for path in files:
        try:
            rel = str(path.relative_to(root)) if root in path.parents else path.name
        except ValueError:
            rel = path.name
        base = path.name.lower()
        if base not in TEMPLATE_FILES and not base.endswith(".jinja"):
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")[: 4 * 1024 * 1024]
        except OSError:
            continue

        if base.endswith(".jinja"):
            pairs: list[tuple[str, str]] = [("<file>", raw)]
        else:
            try:
                pairs = list(_walk_strings(json.loads(raw)))
            except Exception:
                out.append(Finding(
                    "MLSC-TPL-003", f"Unparseable config file: {rel}",
                    Severity.LOW, Category.METADATA, rel,
                    detail=("A config file that should be JSON could not be parsed, "
                            "so its contents were not inspected for templates."),
                    confidence="medium",
                    remediation="Fix or reject the malformed config."))
                continue

        for key, val in pairs:
            is_template_key = any(t in key.lower() for t in TEMPLATE_KEYS)
            if not (is_template_key or JINJA_ANY.search(val)):
                continue
            m = JINJA_EXEC_HINT.search(val)
            if m:
                out.append(Finding(
                    "MLSC-TPL-001",
                    "Chat template contains Python-introspection tokens",
                    Severity.CRITICAL, Category.EXECUTION, rel,
                    detail=("Chat templates are Jinja2 and are rendered at inference "
                            "time, once per request. Tokens like `__class__` or "
                            "`__subclasses__` are the standard Jinja sandbox-escape "
                            "primitives and have no legitimate place in a prompt "
                            "template."),
                    evidence=[f"key={key}", f"token={m.group(0)}", val[:300]],
                    remediation="Reject the template. Render only in a sandboxed "
                                "Jinja environment with no attribute access."))
            elif is_template_key and JINJA_ANY.search(val):
                out.append(Finding(
                    "MLSC-TPL-002", "Chat template present",
                    Severity.INFO, Category.METADATA, rel,
                    detail=("A Jinja chat template will be rendered at inference "
                            "time. No escape primitives detected."),
                    evidence=[f"key={key}", f"length={len(val)}"],
                    confidence="high"))
    return out
