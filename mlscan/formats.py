"""Container-aware scanners: torch zip archives, safetensors, npy, keras, onnx, gguf."""
from __future__ import annotations

import json
import struct
import zipfile
from pathlib import Path

from .findings import Category, Finding, Severity
from .pickle_scan import scan_pickle_blob
from .utils import printable_strings

MAX_MEMBER_READ = 64 * 1024 * 1024      # never buffer more than 64MB of a member
ZIP_RATIO_LIMIT = 200                   # compression-bomb heuristic


def scan_zip_archive(path: Path, display: str) -> list[Finding]:
    out: list[Finding] = []
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        return [Finding(
            rule_id="MLSC-ZIP-000", title="Corrupt zip container",
            severity=Severity.MEDIUM, category=Category.INTEGRITY,
            location=display, detail=str(exc),
            remediation="Re-download and verify checksums.")]

    with zf:
        names = zf.namelist()

        for info in zf.infolist():
            n = info.filename
            if n.startswith("/") or n.startswith("\\") or ".." in Path(n).parts:
                out.append(Finding(
                    rule_id="MLSC-ZIP-001",
                    title="Zip entry escapes the extraction directory",
                    severity=Severity.CRITICAL, category=Category.FILE_ANOMALY,
                    location=f"{display}!{n}",
                    detail=("Archive member uses an absolute path or `..` traversal. "
                            "Extraction could overwrite files outside the target dir "
                            "(e.g. ~/.bashrc, site-packages, sitecustomize.py)."),
                    evidence=[n],
                    remediation="Do not extract. Reject the artifact."))
            # unix symlink bit = 0xA000 in the high 16 bits of external_attr
            if (info.external_attr >> 16) & 0xF000 == 0xA000:
                out.append(Finding(
                    rule_id="MLSC-ZIP-002", title="Symlink entry inside model archive",
                    severity=Severity.HIGH, category=Category.FILE_ANOMALY,
                    location=f"{display}!{n}",
                    detail="Symlinks in a model archive can redirect writes or reads outside the tree.",
                    evidence=[n], remediation="Do not extract."))
            if info.compress_size > 4096 and info.file_size / max(info.compress_size, 1) > ZIP_RATIO_LIMIT:
                out.append(Finding(
                    rule_id="MLSC-ZIP-003", title="Extreme compression ratio (possible zip bomb)",
                    severity=Severity.MEDIUM, category=Category.INTEGRITY,
                    location=f"{display}!{n}",
                    detail=f"ratio {info.file_size / max(info.compress_size,1):.0f}:1",
                    evidence=[f"{info.compress_size} -> {info.file_size} bytes"],
                    confidence="medium",
                    remediation="Cap extraction size; do not decompress untrusted archives in place."))

        pickle_members = [n for n in names
                          if n.endswith((".pkl", ".pickle"))
                          or Path(n).name in {"data.pkl", "constants.pkl", "version"}
                          and n.endswith(".pkl")]
        pickle_members = sorted(set(pickle_members) | {
            n for n in names if Path(n).name == "data.pkl"})
        scanned: set[str] = set()

        for n in pickle_members:
            try:
                info = zf.getinfo(n)
                if info.file_size > MAX_MEMBER_READ:
                    out.append(Finding(
                        rule_id="MLSC-ZIP-004", title="Oversized pickle member skipped",
                        severity=Severity.MEDIUM, category=Category.INTEGRITY,
                        location=f"{display}!{n}",
                        detail=f"member is {info.file_size} bytes; refusing to buffer",
                        confidence="medium", remediation="Inspect manually."))
                    continue
                blob = zf.read(n)
            except Exception as exc:
                out.append(Finding(
                    rule_id="MLSC-ZIP-005", title="Unreadable archive member",
                    severity=Severity.LOW, category=Category.INTEGRITY,
                    location=f"{display}!{n}", detail=str(exc)))
                continue
            scanned.add(n)
            out.extend(scan_pickle_blob(blob, f"{display}!{n}"))

        # .npz / any zip may embed object-dtype .npy (pickle by another name).
        # Detect by magic bytes, not extension — a renamed member still counts.
        for info in zf.infolist():
            n = info.filename
            if n in scanned or info.is_dir() or info.file_size > MAX_MEMBER_READ:
                continue
            try:
                blob = zf.read(n)
            except Exception as exc:
                out.append(Finding(
                    rule_id="MLSC-ZIP-005", title="Unreadable archive member",
                    severity=Severity.LOW, category=Category.INTEGRITY,
                    location=f"{display}!{n}", detail=str(exc)))
                continue
            if blob[:6] == b"\x93NUMPY":
                scanned.add(n)
                out.extend(scan_npy_bytes(blob, f"{display}!{n}"))
            elif blob[:1] == b"\x80":
                scanned.add(n)
                out.extend(scan_pickle_blob(blob, f"{display}!{n}"))

        for n in names:
            suffix = Path(n).suffix.lower()
            if suffix in {".py", ".sh", ".exe", ".dll", ".so", ".dylib", ".bat", ".ps1"}:
                out.append(Finding(
                    rule_id="MLSC-ZIP-006",
                    title=f"Executable/script member bundled in model archive ({suffix})",
                    severity=Severity.HIGH, category=Category.FILE_ANOMALY,
                    location=f"{display}!{n}",
                    detail="Weight archives should contain tensors and metadata only.",
                    evidence=[n], remediation="Inspect the member; treat repo as untrusted."))

        if any(Path(n).name == "code" or n.endswith("/code/") or "/code/" in n for n in names):
            code_members = [n for n in names if "/code/" in n and n.endswith(".py")]
            if code_members:
                out.append(Finding(
                    rule_id="MLSC-ZIP-007",
                    title="TorchScript archive contains serialized Python source",
                    severity=Severity.MEDIUM, category=Category.EXECUTION,
                    location=display,
                    detail=("torch.jit archives embed a `code/` directory that is "
                            "compiled by the TorchScript interpreter on load."),
                    evidence=code_members[:5], confidence="medium",
                    remediation="Review the embedded source before torch.jit.load()."))

        if "config.json" in names:
            try:
                out.extend(_scan_keras_config(zf.read("config.json"), f"{display}!config.json"))
            except Exception as exc:
                out.append(Finding(
                    rule_id="MLSC-ZIP-005", title="Unreadable archive member",
                    severity=Severity.LOW, category=Category.INTEGRITY,
                    location=f"{display}!config.json", detail=str(exc)))

    return out


def _scan_keras_config(blob: bytes, display: str) -> list[Finding]:
    """Inspect Keras model config JSON for code-execution primitives.

    Lambda layers marshal bytecode. Custom objects whose `module` is outside
    the keras/tensorflow namespaces resolve to attacker-controlled classes —
    that is how a `.keras` archive loads code that never appears as a `.py`
    file next to the weights.
    """
    out: list[Finding] = []
    try:
        cfg = json.loads(blob)
    except Exception:
        return out
    text = json.dumps(cfg)
    if '"Lambda"' in text or '"class_name": "Lambda"' in text:
        out.append(Finding(
            rule_id="MLSC-KRS-001", title="Keras Lambda layer present",
            severity=Severity.HIGH, category=Category.EXECUTION,
            location=display,
            detail=("Lambda layers serialize a marshalled Python code object that is "
                    "executed when the model is loaded. This is a documented RCE path "
                    "unless the model is loaded with safe_mode=True."),
            evidence=["Lambda layer found in model config"],
            remediation="Load only with keras.models.load_model(..., safe_mode=True), or reject.",
            references=["https://keras.io/api/models/model_saving_apis/"]))
    if '"registered_name"' in text and '"module": "builtins"' in text:
        out.append(Finding(
            rule_id="MLSC-KRS-002", title="Keras config references builtins module",
            severity=Severity.HIGH, category=Category.EXECUTION,
            location=display,
            detail="A custom object resolves into `builtins`, a common deserialization gadget.",
            confidence="medium",
            remediation="Reject or load with safe_mode=True and an explicit custom_objects allowlist."))

    stack = [cfg]
    seen_mods: list[str] = []
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            mod = cur.get("module")
            if isinstance(mod, str) and mod and not any(
                    mod == p or mod.startswith(p + ".") for p in
                    ("keras", "tensorflow", "tf", "tf_keras")):
                if mod not in seen_mods:
                    seen_mods.append(mod)
                    name = cur.get("registered_name") or cur.get("class_name") or "?"
                    out.append(Finding(
                        rule_id="MLSC-KRS-003",
                        title=f"Keras config loads custom class from `{mod}`",
                        severity=Severity.HIGH, category=Category.EXECUTION,
                        location=display,
                        detail=("A layer/object declares a `module` outside the standard "
                                "Keras/TensorFlow namespace. On load, Keras imports that "
                                "module and instantiates the named class — code execution "
                                "from whatever the archive (or PYTHONPATH) supplies."),
                        evidence=[f"module={mod}", f"name={name}"],
                        remediation="Reject, or load with safe_mode=True and an explicit "
                                    "custom_objects allowlist that does not include this module."))
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)
    return out

STF_DTYPE_BYTES = {
    "F64": 8, "I64": 8, "U64": 8,
    "F32": 4, "I32": 4, "U32": 4,
    "F16": 2, "BF16": 2, "I16": 2, "U16": 2,
    "I8": 1, "U8": 1, "BOOL": 1, "F8_E4M3": 1, "F8_E5M2": 1,
}


def scan_safetensors(path: Path, display: str) -> list[Finding]:
    out: list[Finding] = []
    size = path.stat().st_size
    with open(path, "rb") as fh:
        raw = fh.read(8)
        if len(raw) < 8:
            return [Finding("MLSC-STF-000", "Truncated safetensors file",
                            Severity.MEDIUM, Category.INTEGRITY, display)]
        n = int.from_bytes(raw, "little")
        if n <= 0 or n > size:
            return [Finding(
                rule_id="MLSC-STF-001", title="safetensors header length exceeds file size",
                severity=Severity.HIGH, category=Category.INTEGRITY, location=display,
                detail=f"declared header {n} bytes, file is {size} bytes",
                remediation="Reject; file is malformed or crafted to trigger a parser bug.")]
        if n > 100 * 1024 * 1024:
            out.append(Finding(
                "MLSC-STF-002", "Abnormally large safetensors header",
                Severity.MEDIUM, Category.INTEGRITY, display,
                detail=f"{n} byte JSON header; possible parser DoS",
                confidence="medium"))
        try:
            header = json.loads(fh.read(n))
        except Exception as exc:
            return out + [Finding("MLSC-STF-003", "Unparseable safetensors header",
                                  Severity.HIGH, Category.INTEGRITY, display, detail=str(exc))]

    data_start = 8 + n
    meta = header.pop("__metadata__", {}) if isinstance(header, dict) else {}
    spans: list[tuple[int, int, str]] = []
    for name, spec in (header or {}).items():
        if not isinstance(spec, dict) or "data_offsets" not in spec:
            continue
        try:
            b, e = spec["data_offsets"]
        except Exception:
            continue
        if not isinstance(b, int) or not isinstance(e, int) or b < 0 or e < b:
            out.append(Finding("MLSC-STF-004", "Invalid tensor data offsets",
                               Severity.HIGH, Category.INTEGRITY, display,
                               detail=f"tensor `{name}` offsets {spec['data_offsets']}"))
            continue
        if data_start + e > size:
            out.append(Finding(
                "MLSC-STF-005", "Tensor data offset points past end of file",
                Severity.HIGH, Category.INTEGRITY, display,
                detail=f"tensor `{name}` ends at {data_start + e}, file is {size} bytes",
                remediation="Reject; out-of-bounds read attempt against the parser."))
        dtype = spec.get("dtype")
        shape = spec.get("shape")
        if isinstance(dtype, str) and dtype in STF_DTYPE_BYTES and isinstance(shape, list):
            try:
                nel = 1
                for dim in shape:
                    nel *= int(dim)
                expected = nel * STF_DTYPE_BYTES[dtype]
                declared = e - b
                if expected != declared:
                    out.append(Finding(
                        "MLSC-STF-008",
                        "Tensor shape×dtype does not match data_offsets span",
                        Severity.HIGH, Category.INTEGRITY, display,
                        detail=(f"tensor `{name}` declares shape {shape} dtype {dtype} "
                                f"({expected} bytes) but data_offsets span {declared} bytes. "
                                "A mismatched header is malformed and can confuse loaders."),
                        evidence=[f"expected={expected}", f"span={declared}"],
                        remediation="Reject; regenerate or obtain a well-formed safetensors file."))
            except (TypeError, ValueError):
                pass
        spans.append((b, e, name))

    spans.sort()
    for (b1, e1, n1), (b2, e2, n2) in zip(spans, spans[1:]):
        if b2 < e1:
            out.append(Finding(
                "MLSC-STF-006", "Overlapping tensor regions in safetensors file",
                Severity.MEDIUM, Category.INTEGRITY, display,
                detail=f"`{n1}` [{b1}:{e1}] overlaps `{n2}` [{b2}:{e2}]",
                confidence="medium"))
            break

    if isinstance(meta, dict) and meta:
        big = {k: v for k, v in meta.items() if isinstance(v, str) and len(v) > 4096}
        if big:
            out.append(Finding(
                "MLSC-STF-007", "Very large free-text values in safetensors __metadata__",
                Severity.LOW, Category.METADATA, display,
                detail="__metadata__ is arbitrary attacker-controlled text (a stego/payload channel).",
                evidence=[f"{k}: {len(v)} chars" for k, v in list(big.items())[:5]],
                confidence="low"))
    return out


def scan_npy_bytes(data: bytes, display: str) -> list[Finding]:
    """Parse a NumPy `.npy` buffer without calling `np.load`.

    Object-dtype arrays store a pickle stream after the header. That is the
    same execution primitive as a bare `.pkl`, just wearing a scientific-array
    costume — so we flag it at HIGH and never deserialize the payload.
    """
    if len(data) < 10 or data[:6] != b"\x93NUMPY":
        return [Finding(
            "MLSC-NPY-000", "Unreadable or truncated numpy .npy buffer",
            Severity.LOW, Category.INTEGRITY, display,
            detail="Magic bytes missing or buffer too short to parse.",
            confidence="medium")]
    try:
        major = data[6]
        if major == 1:
            hlen = struct.unpack_from("<H", data, 8)[0]
            hoff = 10
        else:
            hlen = struct.unpack_from("<I", data, 8)[0]
            hoff = 12
        header = data[hoff:hoff + hlen].decode("latin-1")
    except Exception as exc:
        return [Finding(
            "MLSC-NPY-000", "Failed to parse numpy .npy header",
            Severity.MEDIUM, Category.INTEGRITY, display,
            detail=str(exc), confidence="medium")]
    if "'descr': '|O'" in header or '"descr": "|O"' in header or "|O" in header:
        return [Finding(
            rule_id="MLSC-NPY-001", title="numpy object array (pickle inside .npy)",
            severity=Severity.HIGH, category=Category.SERIALIZATION, location=display,
            detail=("dtype `object` arrays are stored as a pickle stream. np.load with "
                    "allow_pickle=True will execute it."),
            evidence=[header.strip()[:200]],
            remediation="Never call np.load(..., allow_pickle=True) on untrusted files.")]
    return []


def scan_npy(path: Path, display: str) -> list[Finding]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [Finding(
            "MLSC-NPY-000", "Unreadable numpy .npy file",
            Severity.LOW, Category.INTEGRITY, display, detail=str(exc))]
    if len(data) > MAX_MEMBER_READ:
        return [Finding(
            "MLSC-NPY-000", "Oversized numpy .npy skipped",
            Severity.MEDIUM, Category.INTEGRITY, display,
            detail=f"{len(data)} bytes exceeds {MAX_MEMBER_READ} byte buffer limit",
            confidence="medium")]
    return scan_npy_bytes(data, display)


def scan_npz(path: Path, display: str) -> list[Finding]:
    """`.npz` is a ZIP of `.npy` members — recurse with the same object-dtype logic."""
    out: list[Finding] = []
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.file_size > MAX_MEMBER_READ:
                    out.append(Finding(
                        "MLSC-ZIP-004", "Oversized .npz member skipped",
                        Severity.MEDIUM, Category.INTEGRITY, f"{display}!{info.filename}",
                        detail=f"member is {info.file_size} bytes; refusing to buffer",
                        confidence="medium"))
                    continue
                try:
                    blob = zf.read(info.filename)
                except Exception as exc:
                    out.append(Finding(
                        "MLSC-ZIP-005", "Unreadable .npz member",
                        Severity.LOW, Category.INTEGRITY, f"{display}!{info.filename}",
                        detail=str(exc)))
                    continue
                if blob[:6] == b"\x93NUMPY":
                    out.extend(scan_npy_bytes(blob, f"{display}!{info.filename}"))
    except zipfile.BadZipFile as exc:
        return [Finding(
            "MLSC-ZIP-000", "Corrupt .npz container",
            Severity.MEDIUM, Category.INTEGRITY, display, detail=str(exc))]
    return out


def scan_hdf5(path: Path, display: str, probe: int = 4 * 1024 * 1024) -> list[Finding]:
    out: list[Finding] = []
    with open(path, "rb") as fh:
        head = fh.read(probe)
    text = head.decode("latin-1", "ignore")
    if '"class_name": "Lambda"' in text or '"class_name":"Lambda"' in text:
        out.append(Finding(
            "MLSC-H5-001", "Keras Lambda layer in HDF5 model", Severity.HIGH,
            Category.EXECUTION, display,
            detail=("The embedded model_config contains a Lambda layer whose marshalled "
                    "code object is executed at load time."),
            remediation="Reject, or reconstruct the architecture manually and load weights only."))
    for marker, why in (("__reduce__", "pickle reduce protocol reference"),
                        ("os.system", "shell command literal"),
                        ("subprocess", "subprocess literal"),
                        ("eval(", "eval literal")):
        if marker in text:
            out.append(Finding(
                "MLSC-H5-002", f"Suspicious literal in HDF5 attributes: {marker}",
                Severity.MEDIUM, Category.EXECUTION, display,
                detail=why, confidence="low",
                remediation="Inspect the attribute manually with h5py."))
    return out

SUSPECT_ONNX_OPS = {"PythonOp", "ATen", "Custom", "com.microsoft", "ai.onnx.contrib"}


def scan_onnx(path: Path, display: str, probe: int = 8 * 1024 * 1024) -> list[Finding]:
    out: list[Finding] = []
    with open(path, "rb") as fh:
        head = fh.read(probe)
    strs = set(printable_strings(head, 4))
    hits = sorted(SUSPECT_ONNX_OPS & strs)
    if hits:
        out.append(Finding(
            "MLSC-ONX-001", "ONNX graph references custom/foreign operators",
            Severity.MEDIUM, Category.EXECUTION, display,
            detail=("Custom operator domains are resolved to native shared libraries "
                    "at session-creation time, outside the ONNX safety envelope."),
            evidence=hits[:8], confidence="medium",
            remediation="Run with a restricted op allowlist; audit any custom op library."))
    if "location" in strs and any(".." in s or s.startswith("/") for s in strs if len(s) < 200):
        sus = [s for s in strs if (".." in s or s.startswith("/")) and len(s) < 200][:5]
        out.append(Finding(
            "MLSC-ONX-002", "Possible external-data path traversal in ONNX model",
            Severity.MEDIUM, Category.FILE_ANOMALY, display,
            detail="ONNX external tensor `location` fields must be relative and contained.",
            evidence=sus, confidence="low",
            remediation="Validate external data paths before loading."))
    return out

SUSPECT_TF_OPS = {"PyFunc", "PyFuncStateless", "ReadFile", "WriteFile",
                  "MergeV2Checkpoints", "Save", "SaveV2", "ShardedFilename"}


def scan_tf_protobuf(path: Path, display: str, probe: int = 8 * 1024 * 1024) -> list[Finding]:
    with open(path, "rb") as fh:
        head = fh.read(probe)
    strs = set(printable_strings(head, 4))
    hits = sorted(SUSPECT_TF_OPS & strs)
    if not hits:
        return []
    sev = Severity.HIGH if {"PyFunc", "WriteFile"} & set(hits) else Severity.MEDIUM
    return [Finding(
        "MLSC-TF-001", "TensorFlow graph contains filesystem/native-callback ops",
        sev, Category.EXECUTION, display,
        detail=("SavedModel graphs can read and write arbitrary paths and call back "
                "into Python during session.run(). These ops are the documented "
                "TF model attack surface."),
        evidence=hits, confidence="medium",
        remediation="Load in a sandbox with no filesystem access, or reject.")]


def scan_gguf(path: Path, display: str) -> list[Finding]:
    with open(path, "rb") as fh:
        head = fh.read(24)
    if len(head) < 8 or head[:4] != b"GGUF":
        return []
    version = int.from_bytes(head[4:8], "little")
    out = [Finding(
        "MLSC-GGUF-001", "GGUF weights (no code execution on load)",
        Severity.INFO, Category.SERIALIZATION, display,
        detail=f"GGUF v{version}. Data-only container; risk is limited to parser memory-safety bugs.",
        remediation="Keep llama.cpp / GGUF runtimes patched.")]
    if version > 3 or version < 1:
        out.append(Finding(
            "MLSC-GGUF-002", "Unexpected GGUF version field",
            Severity.LOW, Category.INTEGRITY, display,
            detail=f"version={version}", confidence="low"))
    return out
