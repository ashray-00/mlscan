"""Static pickle analysis.

The whole point of this module: determine what a pickle stream *would* do
when loaded, WITHOUT ever calling pickle.load(). We do that by walking the
opcode stream with `pickletools.genops`, which is a pure parser.

Threat model recap
------------------
Pickle is a stack VM. Two opcodes give an attacker arbitrary imports:
    GLOBAL        (b'c')   -> push module.attr, args given as text
    STACK_GLOBAL  (b'\\x93') -> push module.attr, args popped from the stack
and four opcodes let them *call* things:
    REDUCE  (b'R')   callable(*args)
    INST    (b'i')   legacy: import + call
    OBJ     (b'o')   legacy: call class from stack
    NEWOBJ  (b'\\x81') / NEWOBJ_EX (b'\\x92')  cls.__new__(cls, *args)
plus BUILD (b'b') which invokes __setstate__ on an attacker-chosen object.

So: `GLOBAL os system` + `REDUCE` == os.system(arg). That is the entire
classic exploit. Detection is therefore "which globals are imported, and is
there a call opcode".
"""
from __future__ import annotations

import io
import pickletools
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Category, Finding, Severity

CRITICAL_GLOBALS: dict[tuple[str, str], str] = {
    ("os", "system"): "shell command execution",
    ("os", "popen"): "shell command execution",
    ("os", "execv"): "process replacement",
    ("os", "execve"): "process replacement",
    ("os", "execl"): "process replacement",
    ("os", "spawnl"): "process spawn",
    ("os", "spawnv"): "process spawn",
    ("os", "fork"): "process fork",
    ("os", "remove"): "file deletion",
    ("os", "unlink"): "file deletion",
    ("os", "rmdir"): "directory deletion",
    ("os", "chmod"): "permission change",
    ("os", "putenv"): "environment tampering",
    ("posix", "system"): "shell command execution",
    ("nt", "system"): "shell command execution",
    ("subprocess", "run"): "subprocess execution",
    ("subprocess", "call"): "subprocess execution",
    ("subprocess", "check_call"): "subprocess execution",
    ("subprocess", "check_output"): "subprocess execution",
    ("subprocess", "Popen"): "subprocess execution",
    ("subprocess", "getoutput"): "subprocess execution",
    ("builtins", "eval"): "arbitrary expression evaluation",
    ("builtins", "exec"): "arbitrary code execution",
    ("builtins", "compile"): "code object construction",
    ("builtins", "__import__"): "dynamic import",
    ("builtins", "getattr"): "attribute pivot (gadget chaining)",
    ("builtins", "setattr"): "attribute overwrite",
    ("builtins", "open"): "arbitrary file access",
    ("builtins", "breakpoint"): "debugger entry (PYTHONBREAKPOINT hijack)",
    ("builtins", "input"): "interactive prompt",
    ("__builtin__", "eval"): "arbitrary expression evaluation (py2)",
    ("__builtin__", "exec"): "arbitrary code execution (py2)",
    ("__builtin__", "compile"): "code object construction (py2)",
    ("__builtin__", "__import__"): "dynamic import (py2)",
    ("__builtin__", "open"): "arbitrary file access (py2)",
    ("runpy", "_run_code"): "module execution",
    ("runpy", "run_path"): "module execution",
    ("runpy", "run_module"): "module execution",
    ("importlib", "import_module"): "dynamic import",
    ("importlib.machinery", "SourceFileLoader"): "loader abuse",
    ("pty", "spawn"): "interactive shell spawn",
    ("pdb", "run"): "debugger code execution",
    ("bdb", "run"): "debugger code execution",
    ("timeit", "timeit"): "eval of arbitrary statement",
    ("code", "interact"): "interactive interpreter",
    ("codeop", "compile_command"): "code compilation",
    ("commands", "getoutput"): "shell command execution (py2)",
    ("popen2", "popen2"): "shell command execution (py2)",
    ("platform", "popen"): "shell command execution",
    ("venv", "create"): "arbitrary command via env hook",
    ("sysconfig", "_main"): "code execution gadget",
}

HIGH_GLOBALS: dict[tuple[str, str], str] = {
    ("socket", "socket"): "raw network socket",
    ("socket", "create_connection"): "outbound network connection",
    ("urllib.request", "urlopen"): "outbound HTTP request",
    ("urllib.request", "urlretrieve"): "remote file download",
    ("urllib", "urlopen"): "outbound HTTP request (py2)",
    ("requests", "get"): "outbound HTTP request",
    ("requests", "post"): "outbound HTTP request (exfiltration)",
    ("http.client", "HTTPSConnection"): "outbound HTTP request",
    ("ftplib", "FTP"): "outbound FTP",
    ("smtplib", "SMTP"): "outbound mail",
    ("shutil", "rmtree"): "recursive deletion",
    ("shutil", "copy"): "file copy",
    ("shutil", "move"): "file move",
    ("ctypes", "CDLL"): "native library load",
    ("ctypes", "WinDLL"): "native library load",
    ("ctypes", "cdll"): "native library load",
    ("multiprocessing", "Process"): "process spawn",
    ("threading", "Thread"): "background thread",
    ("webbrowser", "open"): "URL handler invocation",
    ("pickle", "loads"): "nested pickle (payload unwrapping)",
    ("pickle", "load"): "nested pickle (payload unwrapping)",
    ("_pickle", "loads"): "nested pickle (payload unwrapping)",
    ("dill", "loads"): "nested pickle (payload unwrapping)",
    ("torch", "load"): "nested torch.load (payload unwrapping)",
    ("torch.serialization", "load"): "nested torch.load",
    ("torch.storage", "_load_from_bytes"): "calls torch.load on raw bytes",
    ("pandas", "read_pickle"): "nested pickle",
    ("joblib", "load"): "nested pickle",
    ("numpy", "load"): "np.load (pickle if allow_pickle)",
    ("numpy.testing._private.utils", "runstring"): "known eval gadget",
    ("numpy.testing", "runstring"): "known eval gadget",
    ("sys", "exit"): "interpreter control",
    ("operator", "attrgetter"): "attribute pivot (gadget chaining)",
    ("operator", "methodcaller"): "method pivot (gadget chaining)",
    ("functools", "partial"): "deferred call construction",
    ("functools", "reduce"): "call chaining gadget",
    ("types", "FunctionType"): "function object construction from code",
    ("types", "CodeType"): "raw code object construction",
    ("marshal", "loads"): "code object deserialization",
    ("base64", "b64decode"): "payload decoding",
    ("zlib", "decompress"): "payload decoding",
    ("bz2", "decompress"): "payload decoding",
    ("lzma", "decompress"): "payload decoding",
    ("gzip", "decompress"): "payload decoding",
    ("tempfile", "mktemp"): "temp file staging",
    ("shlex", "split"): "command construction",
    ("getattr", "getattr"): "attribute pivot",
}

WATCH_GLOBALS: dict[tuple[str, str], str] = {
    ("_codecs", "encode"): "used legitimately by numpy, also common in obfuscated payloads",
    ("codecs", "encode"): "encoding helper, common in obfuscated payloads",
    ("codecs", "decode"): "encoding helper, common in obfuscated payloads",
}

ALLOWED_MODULE_PREFIXES = (
    "torch._utils",
    "torch.nn",
    "torch.optim",
    "torch.storage",       # storage *classes* are fine; the method is denied above
    "torch.Tensor",
    "torch.FloatStorage",
    "torch.serialization",  # class refs only; .load is denied above
    "collections",
    "numpy.core.multiarray",
    "numpy._core.multiarray",
    "numpy.core.numeric",
    "numpy._core.numeric",
    "numpy.dtype",
    "numpy.ndarray",
    "numpy.random",
    "numpy",
    "scipy.sparse",
    "sklearn",
    "pandas.core",
    "transformers",
    "tokenizers",
    "argparse",
    "fairseq",
    "omegaconf",
    "__builtin__.set",
)

ALLOWED_EXACT = {
    ("torch", "Tensor"), ("torch", "device"), ("torch", "Size"),
    ("torch", "FloatStorage"), ("torch", "HalfStorage"), ("torch", "LongStorage"),
    ("torch", "IntStorage"), ("torch", "ByteStorage"), ("torch", "BoolStorage"),
    ("torch", "BFloat16Storage"), ("torch", "DoubleStorage"),
    ("torch", "ShortStorage"), ("torch", "CharStorage"),
    ("torch", "float32"), ("torch", "float16"), ("torch", "bfloat16"),
    ("torch", "int64"), ("torch", "int8"), ("torch", "uint8"),
    ("collections", "OrderedDict"), ("collections", "defaultdict"),
    ("builtins", "set"), ("builtins", "frozenset"), ("builtins", "dict"),
    ("builtins", "list"), ("builtins", "tuple"), ("builtins", "int"),
    ("builtins", "float"), ("builtins", "str"), ("builtins", "bytes"),
    ("builtins", "complex"), ("builtins", "bytearray"), ("builtins", "object"),
    ("copyreg", "_reconstructor"),
    ("numpy", "dtype"), ("numpy", "ndarray"), ("numpy", "float32"),
}

CALL_OPCODES = {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}
STRING_PUSH_OPCODES = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING", "BINBYTES", "SHORT_BINBYTES",
}

@dataclass
class PickleAnalysis:
    protocol: int | None = None
    opcode_count: int = 0
    globals_found: list[tuple[str, str, int]] = field(default_factory=list)
    call_opcodes: list[tuple[str, int]] = field(default_factory=list)
    ext_opcodes: list[tuple[str, int]] = field(default_factory=list)
    string_constants: list[str] = field(default_factory=list)
    truncated: bool = False
    parse_error: str | None = None
    trailing_bytes: int = 0
    stop_pos: int | None = None
    opcodes: list[tuple[str, object, int]] = field(default_factory=list)


def analyze_pickle_bytes(data: bytes, max_strings: int = 200) -> PickleAnalysis:
    """Walk the opcode stream. Never executes anything."""
    a = PickleAnalysis()
    # Minimal shadow stack: we only need to resolve STACK_GLOBAL's two operands.
    strings: list[str] = []
    last_pos = 0
    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
            a.opcode_count += 1
            last_pos = pos
            name = opcode.name
            a.opcodes.append((name, arg, pos))

            if name == "PROTO":
                a.protocol = arg
            elif name in STRING_PUSH_OPCODES:
                if isinstance(arg, bytes):
                    try:
                        arg = arg.decode("utf-8", "replace")
                    except Exception:
                        arg = repr(arg)
                strings.append(arg)
                if len(a.string_constants) < max_strings:
                    a.string_constants.append(arg)
            elif name == "GLOBAL":
                mod, _, attr = (arg or "").partition(" ")
                a.globals_found.append((mod, attr, pos))
            elif name == "STACK_GLOBAL":
                if len(strings) >= 2:
                    a.globals_found.append((strings[-2], strings[-1], pos))
                    del strings[-2:]
                else:
                    a.globals_found.append(("<unresolved>", "<unresolved>", pos))
            elif name == "INST":
                mod, _, attr = (arg or "").partition(" ")
                a.globals_found.append((mod, attr, pos))
                a.call_opcodes.append((name, pos))
            elif name in CALL_OPCODES:
                a.call_opcodes.append((name, pos))
            elif name in {"EXT1", "EXT2", "EXT4"}:
                a.ext_opcodes.append((name, pos))
            elif name == "STOP":
                # STOP's recorded pos is the opcode offset; consumed length is pos+1.
                a.stop_pos = pos + 1
                a.trailing_bytes = max(0, len(data) - a.stop_pos)
    except Exception as exc:  # malformed/truncated stream
        a.truncated = True
        a.parse_error = f"{type(exc).__name__}: {exc}"
        a.trailing_bytes = max(0, len(data) - last_pos)
    return a

@dataclass
class Disassembly:
    """View model for `mlscan explain` — analysis plus import aliases."""
    protocol: int | None
    opcodes: list[tuple[str, object, int]]
    imports: list[tuple[str, str, int]]
    reduce_count: int
    stop_pos: int | None
    parse_error: str | None
    trailing_bytes: int = 0


def disassemble(data: bytes) -> Disassembly:
    a = analyze_pickle_bytes(data)
    return Disassembly(
        protocol=a.protocol,
        opcodes=a.opcodes,
        imports=list(a.globals_found),
        reduce_count=sum(1 for n, _ in a.call_opcodes if n in CALL_OPCODES),
        stop_pos=a.stop_pos,
        parse_error=a.parse_error,
        trailing_bytes=a.trailing_bytes,
    )


def classify_global(module: str, attr: str) -> tuple[str, str, str]:
    """Return (bucket, severity, reason) for explain / globals_db callers.

    bucket is deny | allow | unknown.
    """
    if _is_allowed(module, attr) and _severity_for(module, attr) is None:
        return "allow", "INFO", "framework allowlist"
    verdict = _severity_for(module, attr)
    if verdict:
        sev, why = verdict
        return "deny", sev.value, why
    if _is_allowed(module, attr):
        return "allow", "INFO", "framework allowlist"
    return "unknown", "MEDIUM", "not on the framework allowlist"


def _severity_for(mod: str, attr: str) -> tuple[Severity, str] | None:
    key = (mod, attr)
    if key in CRITICAL_GLOBALS:
        return Severity.CRITICAL, CRITICAL_GLOBALS[key]
    if key in HIGH_GLOBALS:
        return Severity.HIGH, HIGH_GLOBALS[key]
    if key in WATCH_GLOBALS:
        return Severity.MEDIUM, WATCH_GLOBALS[key]
    # Module-level denial: any attribute of these modules is dangerous.
    if mod in {"os", "posix", "nt", "subprocess", "sys", "socket", "shutil",
               "ctypes", "pty", "importlib", "runpy", "marshal", "pickle",
               "_pickle", "dill", "cloudpickle"}:
        return Severity.CRITICAL, f"import of dangerous module `{mod}`"
    if mod in {"requests", "urllib", "urllib.request", "http", "http.client",
               "ftplib", "smtplib", "telnetlib", "paramiko", "asyncio"}:
        return Severity.HIGH, f"network-capable module `{mod}`"
    return None


def _is_allowed(mod: str, attr: str) -> bool:
    if (mod, attr) in ALLOWED_EXACT:
        return True
    return any(mod == p or mod.startswith(p + ".") for p in ALLOWED_MODULE_PREFIXES)


def findings_from_analysis(a: PickleAnalysis, location: str) -> list[Finding]:
    out: list[Finding] = []
    has_call = bool(a.call_opcodes)
    call_names = sorted({n for n, _ in a.call_opcodes})

    seen: set[tuple[str, str]] = set()
    for mod, attr, pos in a.globals_found:
        if (mod, attr) in seen:
            continue
        seen.add((mod, attr))

        verdict = _severity_for(mod, attr)
        if verdict:
            sev, why = verdict
            # A dangerous import with no call opcode is still bad, but one
            # notch lower -- it means the payload is staged, not obviously armed.
            if not has_call and sev is Severity.CRITICAL:
                sev = Severity.HIGH
            out.append(Finding(
                rule_id="MLSC-PKL-001",
                title=f"Dangerous global imported by pickle: {mod}.{attr}",
                severity=sev,
                category=Category.EXECUTION,
                location=location,
                detail=(f"The pickle stream imports `{mod}.{attr}` ({why}). "
                        f"Call opcodes present: {call_names or 'none'}. "
                        "Loading this file with torch.load / pickle.load would "
                        "execute this reference."),
                evidence=[f"opcode offset {pos}: GLOBAL {mod} {attr}"],
                remediation=("Do not load this file. Obtain weights in "
                             "safetensors format from a trusted source."),
                references=["https://docs.python.org/3/library/pickle.html#restricting-globals"],
            ))
        elif not _is_allowed(mod, attr):
            out.append(Finding(
                rule_id="MLSC-PKL-002",
                title=f"Unrecognised global imported by pickle: {mod}.{attr}",
                severity=Severity.MEDIUM if has_call else Severity.LOW,
                category=Category.EXECUTION,
                location=location,
                detail=(f"`{mod}.{attr}` is not on the framework allowlist. This is "
                        "often benign (custom research code) but every import in a "
                        "pickle is an execution primitive and must be reviewed."),
                evidence=[f"opcode offset {pos}: GLOBAL {mod} {attr}"],
                confidence="medium",
                remediation="Manually verify this symbol, or re-export to safetensors.",
            ))

    if a.ext_opcodes:
        out.append(Finding(
            rule_id="MLSC-PKL-003",
            title="Pickle uses EXT opcodes (copyreg extension registry)",
            severity=Severity.HIGH,
            category=Category.EXECUTION,
            location=location,
            detail=("EXT1/EXT2/EXT4 resolve objects through the copyreg extension "
                    "registry rather than a named import, which hides the target "
                    "from naive scanners."),
            evidence=[f"{n} at offset {p}" for n, p in a.ext_opcodes[:5]],
            remediation="Treat as untrusted; do not load.",
        ))

    if a.truncated:
        out.append(Finding(
            rule_id="MLSC-PKL-004",
            title="Malformed or truncated pickle stream",
            severity=Severity.MEDIUM,
            category=Category.INTEGRITY,
            location=location,
            detail=("The opcode stream could not be fully parsed. This can indicate "
                    "corruption, or a deliberate attempt to break static scanners "
                    "while remaining loadable by a permissive unpickler."),
            evidence=[a.parse_error or "unknown parse error"],
            confidence="medium",
            remediation="Do not load. Re-download from the canonical source and compare hashes.",
        ))

    # Surface obviously shell-ish string constants regardless of globals.
    shell_markers = ("/bin/sh", "/bin/bash", "curl ", "wget ", "nc -", "powershell",
                     "base64 -d", "chmod +x", "http://", "https://", "cmd.exe",
                     "socket.socket", "os.system", "import os", "__import__")
    hits = [s for s in a.string_constants
            if any(m in s for m in shell_markers)][:8]
    if hits:
        out.append(Finding(
            rule_id="MLSC-PKL-005",
            title="Suspicious string constants embedded in pickle",
            severity=Severity.HIGH if any(
                m in s for s in hits
                for m in ("/bin/sh", "curl ", "wget ", "powershell", "cmd.exe")
            ) else Severity.MEDIUM,
            category=Category.EXECUTION,
            location=location,
            detail="Command-like or URL-like literals appear in the pickle payload.",
            evidence=[s[:200] for s in hits],
            confidence="medium",
            remediation="Review the literals; commands or URLs in weights are not normal.",
        ))
    return out


def scan_pickle_file(path: Path, display: str | None = None) -> list[Finding]:
    data = path.read_bytes()
    return scan_pickle_blob(data, display or str(path))


def scan_pickle_blob(data: bytes, display: str) -> list[Finding]:
    a = analyze_pickle_bytes(data)
    out = findings_from_analysis(a, display)
    out.insert(0, Finding(
        rule_id="MLSC-FMT-001",
        title="Pickle-based serialization in use",
        severity=Severity.LOW,
        category=Category.SERIALIZATION,
        location=display,
        detail=(f"Pickle protocol {a.protocol}, {a.opcode_count} opcodes, "
                f"{len(a.globals_found)} global import(s). Pickle deserialization is "
                "equivalent to executing the file."),
        evidence=[f"globals: {sorted({f'{m}.{n}' for m, n, _ in a.globals_found})}"],
        remediation="Prefer .safetensors; convert with `safetensors.torch.save_file`.",
        references=["https://huggingface.co/docs/safetensors/index"],
    ))
    return out
