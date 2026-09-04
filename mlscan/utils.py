"""Low-level helpers: magic-byte sniffing, format classification, hashing."""
from __future__ import annotations

import hashlib
import io
import os
import pickletools
from pathlib import Path

# (prefix_bytes, label, offset)
MAGIC = [
    (b"PK\x03\x04", "zip", 0),
    (b"PK\x05\x06", "zip-empty", 0),
    (b"\x89HDF\r\n\x1a\n", "hdf5", 0),
    (b"GGUF", "gguf", 0),
    (b"\x93NUMPY", "npy", 0),
    (b"\x7fELF", "elf", 0),
    (b"MZ", "pe", 0),
    (b"\xcf\xfa\xed\xfe", "macho64", 0),
    (b"\xce\xfa\xed\xfe", "macho32", 0),
    (b"\xca\xfe\xba\xbe", "macho-fat/java-class", 0),
    (b"\x1f\x8b", "gzip", 0),
    (b"BZh", "bzip2", 0),
    (b"\xfd7zXZ\x00", "xz", 0),
    (b"\x04\x22\x4d\x18", "lz4", 0),
    (b"(\xb5/\xfd", "zstd", 0),
    (b"ustar\x00", "tar", 257),
    (b"ustar  \x00", "tar", 257),
    (b"7z\xbc\xaf\x27\x1c", "7z", 0),
    (b"Rar!\x1a\x07", "rar", 0),
    (b"#!", "script-shebang", 0),
]

PICKLE_PROTO_HEADS = {b"\x80" + bytes([v]) for v in range(6)}
PICKLE_P0_HEADS = set(b"(]}cS VIL\x88\x89NK")

# Extensions whose *load path* can execute attacker-controlled code.
PICKLE_EXTS = {".pkl", ".pickle", ".bin", ".pt", ".pth", ".ckpt", ".dat",
               ".joblib", ".dill", ".model", ".pb2", ".torch"}
SAFE_TENSOR_EXTS = {".safetensors"}
OTHER_MODEL_EXTS = {".gguf", ".ggml", ".onnx", ".msgpack", ".npz", ".npy",
                    ".h5", ".hdf5", ".keras", ".tflite", ".pb", ".mlmodel",
                    ".engine", ".plan", ".pdparams", ".caffemodel"}
CODE_EXTS = {".py", ".pyc", ".pyo", ".pyd", ".sh", ".bash", ".zsh", ".ps1",
             ".bat", ".cmd", ".pl", ".rb", ".js", ".mjs", ".vbs", ".jar",
             ".so", ".dll", ".dylib", ".exe", ".elf", ".bin_exec"}
NOTEBOOK_EXTS = {".ipynb"}
DOC_EXTS = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".cfg",
            ".gitattributes", ".gitignore", ".csv", ".tsv", ".jsonl"}

SAFE_FORMATS = {"safetensors", "gguf", "msgpack", "onnx", "npz-nopickle", "json"}


def sniff(path: Path, nbytes: int = 16) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(nbytes)
    except OSError:
        return b""


def magic_label(head: bytes) -> str:
    for sig, label, off in MAGIC:
        end = off + len(sig)
        if len(head) < end:
            continue
        if head[off:end] == sig:
            return label
    return "unknown"


def is_safetensors(path: Path) -> bool:
    """safetensors = 8-byte LE header length, then a JSON object."""
    head = sniff(path, 9)
    if len(head) < 9:
        return False
    n = int.from_bytes(head[:8], "little")
    return 0 < n < (1 << 32) and head[8:9] == b"{"


def looks_like_pickle(path: Path, head: bytes) -> bool:
    """Protocol 2+ has PROTO (0x80)+version — unambiguous.

    Protocol 0/1 has no magic number, so we require a successful trial parse
    to STOP. That keeps `class Foo: pass` (starts with GLOBAL opcode `c`)
    from being misidentified as a pickle.
    """
    if len(head) >= 2 and head[:2] in PICKLE_PROTO_HEADS:
        return True
    if not head or head[0] not in PICKLE_P0_HEADS:
        return False
    try:
        data = path.read_bytes()[: 4 * 1024 * 1024]
    except OSError:
        return False
    ops = 0
    try:
        for op, _arg, _pos in pickletools.genops(io.BytesIO(data)):
            ops += 1
            if op.name == "STOP":
                return ops >= 2
            if ops > 100_000:
                return True
    except Exception:
        return False
    return False


def classify(path: Path) -> str:
    """Return a coarse format label used for policy decisions."""
    ext = path.suffix.lower()
    head = sniff(path, 300)
    m = magic_label(head)

    if head.startswith(b"version https://git-lfs.github.com/spec/"):
        return "git-lfs-pointer"
    if is_safetensors(path):
        return "safetensors"
    if m == "gguf":
        return "gguf"
    if m == "hdf5":
        return "hdf5"
    if m == "npy":
        return "npy"
    if m == "tar":
        return "tar"
    if m in {"elf", "pe", "macho64", "macho32"}:
        return "native-executable"
    if m == "gzip":
        return "gzip"
    if m == "bzip2":
        return "bzip2"
    if m == "xz":
        return "xz"
    if m == "zstd":
        return "zstd"
    if m == "zip":
        if ext in {".keras"}:
            return "keras-v3"
        if ext in PICKLE_EXTS or ext in {".zip"}:
            return "torch-zip"
        return "zip"
    if looks_like_pickle(path, head):
        return "pickle"
    if ext == ".onnx":
        return "onnx"
    if ext == ".msgpack":
        return "msgpack"
    if ext == ".npz":
        return "npz"
    if ext == ".pb":
        return "tf-protobuf"
    if ext in NOTEBOOK_EXTS:
        return "notebook"
    if ext == ".py":
        return "python-source"
    if ext in CODE_EXTS:
        return "code"
    if ext in DOC_EXTS or path.name in {"README", "LICENSE"}:
        return "text"
    return "unknown"


def identify(path: str | Path) -> str:
    """Public alias used by tests / docs — same as classify()."""
    return classify(Path(path))


def sha256_file(path: Path, limit: int | None = None) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        read = 0
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            read += len(chunk)
            if limit and read >= limit:
                break
    return h.hexdigest()


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def walk_files(root: Path, max_files: int = 20000) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git"}]
        for fn in filenames:
            out.append(Path(dirpath) / fn)
            if len(out) >= max_files:
                return out
    return out


def printable_strings(data: bytes, minlen: int = 5) -> list[str]:
    """Cheap `strings(1)` used by heuristic byte-scanners."""
    out, cur = [], []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append("".join(cur))
    return out
