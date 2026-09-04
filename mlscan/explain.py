"""`mlscan explain` — manual pickle triage.

Prints raw disassembly AND the stack/memo simulation side by side, because the
gap between them is the point: STACK_GLOBAL shows `arg=None` in raw genops,
and only the simulation recovers what is actually being imported.
"""
from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pickletools

from .pickle_scan import classify_global, disassemble

BUCKET_MARK = {"deny": "!!", "unknown": " ?", "allow": "  "}


def _find_pickle_members(path: Path) -> list[tuple[str, str]]:
    """Every zip member that is, or contains, a pickle stream."""
    out: list[tuple[str, str]] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            with zf.open(info) as fh:
                head = fh.read(8)
            if head[:1] == b"\x80" or info.filename.endswith((".pkl", ".pickle")):
                out.append((info.filename, "pickle"))
            elif head.startswith(b"\x93NUMPY"):
                out.append((info.filename, "npy"))
    return out


def _strip_npy(data: bytes) -> bytes:
    """Skip the .npy header to reach an embedded object-array pickle."""
    major = data[6]
    if major == 1:
        hlen = struct.unpack("<H", data[8:10])[0]
        return data[10 + hlen:]
    hlen = struct.unpack("<I", data[8:12])[0]
    return data[12 + hlen:]


def _load_stream(path: Path, member: str | None = None) -> tuple[bytes, str]:
    """Return (bytes, label). Mirrors how `scan` reaches nested pickles."""
    with open(path, "rb") as fh:
        head = fh.read(8)

    if head.startswith(b"PK\x03\x04"):
        if member:
            with zipfile.ZipFile(path) as zf:
                return zf.read(member), f"{path}::{member}"
        members = _find_pickle_members(path)
        if not members:
            raise SystemExit(f"no pickle members found in {path}")
        if len(members) > 1:
            names = "\n  ".join(f"{n} ({k})" for n, k in members)
            raise SystemExit(
                f"{path} contains several streams; pick one with --member:\n  {names}")
        name, kind = members[0]
        with zipfile.ZipFile(path) as zf:
            data = zf.read(name)
        return (_strip_npy(data) if kind == "npy" else data), f"{path}::{name}"

    if head.startswith(b"\x93NUMPY"):
        with open(path, "rb") as fh:
            return _strip_npy(fh.read()), f"{path} (embedded object array)"

    with open(path, "rb") as fh:
        return fh.read(), str(path)


def explain(path: str | Path, member: str | None = None, max_ops: int = 200) -> None:
    path = Path(path)
    data, label = _load_stream(path, member)
    d = disassemble(data)
    import_at = {pos: (m, a) for m, a, pos in d.imports}

    print(f"stream      : {label}")
    print(f"bytes       : {len(data)}")
    print(f"protocol    : {d.protocol}")
    print(f"opcodes     : {len(d.opcodes)}   REDUCE-class calls: {d.reduce_count}")
    if d.stop_pos is not None:
        trailing = len(data) - d.stop_pos
        print(f"STOP offset : {d.stop_pos}"
              + (f"   !! {trailing} trailing bytes after STOP" if trailing else ""))
    if d.parse_error:
        print(f"PARSE ERROR : {d.parse_error}")

    print("\nresolved imports")
    print("-" * 68)
    if not d.imports:
        print("  (none)")
    for module, attr, pos in d.imports:
        bucket, sev, reason = classify_global(module, attr)
        print(f"  {BUCKET_MARK[bucket]} @{pos:<6} {module}.{attr}")
        print(f"       {bucket.upper():8s} {sev:8s} {reason}")

    print("\nopcode trace  (!! = import resolved here)")
    print("-" * 68)
    try:
        for i, (op, arg, pos) in enumerate(pickletools.genops(io.BytesIO(data))):
            if i >= max_ops:
                print(f"  ... {len(d.opcodes) - max_ops} more")
                break
            mark = ""
            if pos in import_at:
                m, a = import_at[pos]
                bucket, _, _ = classify_global(m, a)
                mark = f"   <-- {BUCKET_MARK[bucket].strip() or '  '} {m}.{a}"
            shown = repr(arg) if arg is not None else ""
            print(f"  {pos:6d}  {op.name:20s} {shown:<28}{mark}")
    except Exception as exc:
        print(f"  <trace stopped: {type(exc).__name__}: {exc}>")

    if d.stop_pos is not None and len(data) > d.stop_pos:
        tail = data[d.stop_pos:]
        second = tail[:1] == b"\x80" or (tail[:1] in b"(]}c" if tail else False)
        print(f"\ntrailing region ({len(tail)} bytes)")
        print("-" * 68)
        print(f"  hex : {tail[:32].hex()}")
        print(f"  looks like a second pickle: {second}")
