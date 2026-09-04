"""Repo-level metadata checks + AST analysis of bundled Python (trust_remote_code)."""
from __future__ import annotations

import ast
import json
from pathlib import Path

from .findings import Category, Finding, Severity

DANGEROUS_CALLS = {
    "eval": Severity.HIGH, "exec": Severity.HIGH, "compile": Severity.MEDIUM,
    "__import__": Severity.HIGH, "system": Severity.CRITICAL,
    "popen": Severity.CRITICAL, "Popen": Severity.HIGH, "run": Severity.LOW,
    "check_output": Severity.HIGH, "call": Severity.LOW,
    "urlopen": Severity.HIGH, "urlretrieve": Severity.HIGH,
    "loads": Severity.LOW, "load": Severity.LOW,
    "b64decode": Severity.MEDIUM, "CDLL": Severity.HIGH,
    "spawn": Severity.HIGH, "connect": Severity.MEDIUM,
}
DANGEROUS_IMPORTS = {
    "os": Severity.MEDIUM,
    "subprocess": Severity.HIGH, "socket": Severity.HIGH, "ctypes": Severity.HIGH,
    "pty": Severity.CRITICAL, "telnetlib": Severity.HIGH, "paramiko": Severity.MEDIUM,
    "pickle": Severity.MEDIUM, "marshal": Severity.MEDIUM, "requests": Severity.LOW,
    "urllib": Severity.LOW, "shutil": Severity.LOW, "base64": Severity.LOW,
}


def _looks_like_chr_chain(node: ast.AST) -> bool:
    """True when an expression is built from chr() / ord-style concatenation."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "chr":
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _looks_like_chr_chain(node.left) or _looks_like_chr_chain(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "join":
            return True
    if isinstance(node, ast.JoinedStr):
        return any(_looks_like_chr_chain(v) for v in node.values
                   if isinstance(v, ast.FormattedValue))
    return False


def scan_python_source(path: Path, display: str) -> list[Finding]:
    """AST scan of a .py file shipped alongside weights.

    Two things matter most:
      1. dangerous calls anywhere in the file
      2. *module-level* side effects -- code that runs the instant
         `from_pretrained(..., trust_remote_code=True)` imports the module.
    """
    out: list[Finding] = []
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(src)
    except SyntaxError as exc:
        return [Finding("MLSC-PY-000", "Bundled Python file does not parse",
                        Severity.MEDIUM, Category.FILE_ANOMALY, display,
                        detail=("A syntax error is itself worth a finding: code that is "
                                "valid for the target interpreter but unparseable here is "
                                "a plausible evasion. Falling back without a signal would "
                                "hide that. " + str(exc)),
                        confidence="medium",
                        remediation="Inspect the file manually; do not trust_remote_code.")]
    except Exception:
        return out

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in DANGEROUS_IMPORTS:
                    out.append(Finding(
                        "MLSC-PY-001", f"Bundled code imports `{alias.name}`",
                        DANGEROUS_IMPORTS[root], Category.EXECUTION, display,
                        detail="Model repositories should not need process, network or FFI access.",
                        evidence=[f"line {node.lineno}: import {alias.name}"],
                        remediation="Do not use trust_remote_code=True with this repo."))
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in DANGEROUS_IMPORTS:
                out.append(Finding(
                    "MLSC-PY-001", f"Bundled code imports from `{node.module}`",
                    DANGEROUS_IMPORTS[root], Category.EXECUTION, display,
                    detail="Model repositories should not need process, network or FFI access.",
                    evidence=[f"line {node.lineno}: from {node.module} import ..."],
                    remediation="Do not use trust_remote_code=True with this repo."))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else (fn.attr if isinstance(fn, ast.Attribute) else None)
        if name in DANGEROUS_CALLS:
            sev = DANGEROUS_CALLS[name]
            qual = name
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                qual = f"{fn.value.id}.{name}"
                if qual in {"os.system", "os.popen"}:
                    sev = Severity.CRITICAL
                elif qual in {"json.load", "json.loads", "torch.load"}:
                    sev = Severity.LOW
            if sev.rank >= Severity.MEDIUM.rank:
                out.append(Finding(
                    "MLSC-PY-002", f"Bundled code calls `{qual}`",
                    sev, Category.EXECUTION, display,
                    detail="Dynamic execution / process / network primitive in model code.",
                    evidence=[f"line {node.lineno}: {qual}(...)"],
                    remediation="Review manually; refuse trust_remote_code=True."))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        # getattr(obj, "system") / getattr(__import__("os"), "system")
        if isinstance(fn, ast.Name) and fn.id == "getattr" and len(node.args) >= 2:
            attr = node.args[1]
            if isinstance(attr, ast.Constant) and isinstance(attr.value, str):
                if attr.value in DANGEROUS_CALLS:
                    sev = DANGEROUS_CALLS[attr.value]
                    out.append(Finding(
                        "MLSC-PY-002", f"Bundled code uses getattr(..., '{attr.value}')",
                        sev, Category.EXECUTION, display,
                        detail="Constant-string getattr is a common obfuscation of a dangerous call.",
                        evidence=[f"line {node.lineno}"],
                        remediation="Review manually; refuse trust_remote_code=True."))
        # chr()-built module names: __import__(''.join(map(chr,[111,115])))
        if isinstance(fn, ast.Name) and fn.id in {"__import__", "import_module"}:
            if node.args and _looks_like_chr_chain(node.args[0]):
                out.append(Finding(
                    "MLSC-PY-002", "Bundled code builds a module name via chr()/concat",
                    Severity.HIGH, Category.EXECUTION, display,
                    detail="Obfuscated dynamic import — typical of packed remote-code payloads.",
                    evidence=[f"line {node.lineno}"], confidence="medium",
                    remediation="Refuse trust_remote_code=True."))

    def _contains_call(n: ast.AST) -> bool:
        return any(isinstance(c, ast.Call) for c in ast.walk(n))

    side_effects: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef,
                             ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, ast.Expr):
            if not isinstance(node.value, ast.Constant):
                side_effects.append(node)
            continue
        # Assignments matter when they CALL something, or when they mutate
        # shared state (os.environ['X']=..., sys.path[...]=..., obj.attr=...).
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = getattr(node, "targets", [getattr(node, "target", None)])
            mutates_shared = any(isinstance(t, (ast.Subscript, ast.Attribute))
                                 for t in targets if t is not None)
            if (node.value is not None and _contains_call(node.value)) or mutates_shared:
                side_effects.append(node)
            continue
        # `if __name__ == "__main__":` does not run on import.
        if isinstance(node, ast.If):
            test = node.test
            is_main = (isinstance(test, ast.Compare)
                       and isinstance(test.left, ast.Name)
                       and test.left.id == "__name__")
            if not is_main:
                side_effects.append(node)
            continue
        side_effects.append(node)

    if side_effects:
        out.append(Finding(
            "MLSC-PY-003", "Module-level side effects in bundled model code",
            Severity.MEDIUM, Category.EXECUTION, display,
            detail=("Statements execute at import time. With trust_remote_code=True, "
                    "these run before any model is even instantiated."),
            evidence=[f"line {n.lineno}: {type(n).__name__}" for n in side_effects[:6]],
            confidence="medium",
            remediation="Read these lines before loading the model."))

    long_lits = [n for n in ast.walk(tree)
                 if isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) > 1200]
    if long_lits:
        out.append(Finding(
            "MLSC-PY-004", "Very long string literal in bundled code",
            Severity.MEDIUM, Category.EXECUTION, display,
            detail="Long opaque literals are the usual carrier for encoded payloads.",
            evidence=[f"line {n.lineno}: {len(n.value)} chars" for n in long_lits[:3]],
            confidence="low", remediation="Decode and inspect the literal."))
    return out


def scan_notebook(path: Path, display: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        nb = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return out
    bad: list[str] = []
    severe = False
    for i, cell in enumerate(nb.get("cells", [])):
        if cell.get("cell_type") != "code":
            continue
        src = "".join(cell.get("source", []))
        for line in src.splitlines():
            s = line.strip()
            hit = False
            if s.startswith("!") or s.startswith("%%bash") or s.startswith("%sx"):
                hit = True
            if any(m in s for m in ("os.system", "subprocess", "curl ", "wget ")):
                hit = True
            if hit:
                bad.append(f"cell {i}: {s[:120]}")
            if (("curl" in s or "wget" in s)
                    and ("| sh" in s or "|sh" in s or "| bash" in s
                         or "|bash" in s or "| python" in s)):
                severe = True
            if "eval(" in s and "b64decode" in s:
                severe = True
    if bad:
        out.append(Finding(
            "MLSC-NB-001", "Notebook contains shell escapes or process calls",
            Severity.HIGH if severe else Severity.MEDIUM, Category.EXECUTION, display,
            detail=("Notebooks shipped in model repos are a common delivery vehicle. "
                    + ("A remote download is piped directly into an interpreter, which "
                       "is unauthenticated remote code execution on 'Run All'."
                       if severe else
                       "Shell escapes run with the notebook kernel's full privileges.")),
            evidence=bad[:6], confidence="high" if severe else "medium",
            remediation="Read before running; never 'Run All' on an untrusted notebook."))
    return out


def scan_config_json(path: Path, display: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        cfg = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return [Finding("MLSC-CFG-000", "Unparseable config.json", Severity.LOW,
                        Category.METADATA, display, detail=str(exc))]
    if not isinstance(cfg, dict):
        return out

    if "auto_map" in cfg:
        out.append(Finding(
            "MLSC-CFG-001", "config.json declares `auto_map` (requires trust_remote_code)",
            Severity.HIGH, Category.EXECUTION, display,
            detail=("`auto_map` points transformers at Python modules inside the repo. "
                    "Loading with trust_remote_code=True imports and runs that code with "
                    "the full privileges of your process."),
            evidence=[json.dumps(cfg["auto_map"])[:400]],
            remediation="Read every referenced .py file, or refuse trust_remote_code."))
    if cfg.get("custom_pipeline") or cfg.get("custom_pipelines"):
        out.append(Finding(
            "MLSC-CFG-002", "Custom pipeline declared in config",
            Severity.HIGH, Category.EXECUTION, display,
            detail="diffusers/transformers will fetch and execute the named pipeline module.",
            evidence=[str(cfg.get("custom_pipeline") or cfg.get("custom_pipelines"))[:200]],
            remediation="Refuse, or vendor and review the pipeline code."))
    for key in ("quantization_config", "auto_map", "architectures"):
        val = cfg.get(key)
        if isinstance(val, str) and ("http://" in val or "https://" in val):
            out.append(Finding(
                "MLSC-CFG-003", f"Remote URL embedded in config field `{key}`",
                Severity.MEDIUM, Category.METADATA, display,
                detail="Config values that point off-host can pull code or weights at load time.",
                evidence=[val[:200]], confidence="medium"))
    return out


def scan_repo_consistency(root: Path, files: list[Path]) -> list[Finding]:
    """Cross-file checks that only make sense at repo level."""
    out: list[Finding] = []
    names = {f.name for f in files}
    rels = [str(f.relative_to(root)) for f in files]

    has_safetensors = any(n.endswith(".safetensors") for n in names)
    pickle_like = [r for r in rels if r.endswith((".bin", ".pt", ".pth", ".ckpt", ".pkl"))]

    if pickle_like and not has_safetensors:
        out.append(Finding(
            "MLSC-REPO-001", "Weights available only in pickle-based format",
            Severity.MEDIUM, Category.SERIALIZATION, str(root),
            detail=("No .safetensors sibling exists, so consumers are forced onto the "
                    "unsafe load path. Mature, well-maintained repos publish both."),
            evidence=pickle_like[:8],
            remediation="Request/convert a safetensors build before adopting."))
    elif pickle_like and has_safetensors:
        out.append(Finding(
            "MLSC-REPO-002", "Redundant pickle weights alongside safetensors",
            Severity.LOW, Category.SERIALIZATION, str(root),
            detail=("Safe weights exist, but the pickle files remain a live risk for any "
                    "tool that resolves .bin first."),
            evidence=pickle_like[:8],
            remediation="Delete/ignore the pickle copies; pin use_safetensors=True."))

    py_files = [r for r in rels if r.endswith(".py")]
    cfg = root / "config.json"
    has_auto_map = False
    if cfg.exists():
        try:
            has_auto_map = "auto_map" in json.loads(cfg.read_text(errors="replace"))
        except Exception:
            pass
    if py_files and not has_auto_map:
        out.append(Finding(
            "MLSC-REPO-003", "Python files present but not referenced by config auto_map",
            Severity.MEDIUM, Category.FILE_ANOMALY, str(root),
            detail=("Unreferenced code in a weights repo has no legitimate load-time role; "
                    "it may be staged for a later import or for humans to run."),
            evidence=py_files[:8], confidence="medium",
            remediation="Review each file."))

    if "README.md" not in names:
        out.append(Finding(
            "MLSC-REPO-004", "No model card / README",
            Severity.LOW, Category.PROVENANCE, str(root),
            detail="Absence of documentation is weak evidence of a low-effort or throwaway repo.",
            confidence="low"))

    for risky in ("setup.py", "requirements.txt", "pyproject.toml", "Dockerfile",
                  "install.sh", "run.sh", "entrypoint.sh"):
        if risky in names:
            out.append(Finding(
                "MLSC-REPO-005", f"Build/install artifact in a weights repo: {risky}",
                Severity.MEDIUM, Category.FILE_ANOMALY, str(root),
                detail="Installation scripts execute arbitrary code on `pip install` or `docker build`.",
                evidence=[risky], confidence="medium",
                remediation="Inspect before use; never `pip install` a model repo blindly."))
    return out
