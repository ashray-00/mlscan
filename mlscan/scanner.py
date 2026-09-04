"""Orchestration: turn a target (local dir / file / hub id) into a ScanResult."""
from __future__ import annotations

import bz2
import datetime as _dt
import gzip
import lzma
import tarfile
from pathlib import Path

from . import formats, hub, metadata, pickle_scan, typosquat
from .findings import Category, FileRecord, Finding, ScanResult, ScanTarget, Severity
from .utils import classify, magic_label, sha256_file, sniff, walk_files

# Unexpected in a weights repo.
UNEXPECTED_FORMATS = {
    "native-executable": (Severity.CRITICAL, "compiled native binary"),
    "code": (Severity.HIGH, "script or shared library"),
    "7z": (Severity.MEDIUM, "compressed archive"),
    "rar": (Severity.MEDIUM, "compressed archive"),
}

# extension -> expected magic label(s); mismatch => masquerade
EXT_MAGIC_EXPECT = {
    ".safetensors": {"safetensors"},
    ".gguf": {"gguf"},
    ".json": {"unknown", "text"},
    ".onnx": {"unknown"},
    ".h5": {"hdf5"},
    ".npz": {"zip"},
    ".txt": {"unknown", "text"},
    ".md": {"unknown", "text"},
}

MAX_DECOMPRESSED = 64 * 1024 * 1024
BOMB_RATIO = formats.ZIP_RATIO_LIMIT


def _decompress(data: bytes, fmt: str) -> tuple[bytes | None, list[Finding]]:
    """Decompress a bounded stream; emit findings on bomb / unsupported codec."""
    findings: list[Finding] = []
    try:
        if fmt == "gzip":
            raw = gzip.decompress(data)
        elif fmt == "bzip2":
            raw = bz2.decompress(data)
        elif fmt == "xz":
            raw = lzma.decompress(data)
        elif fmt == "zstd":
            try:
                from compression import zstd  # Python 3.14+
                raw = zstd.decompress(data)
            except ImportError:
                findings.append(Finding(
                    "MLSC-ENG-003",
                    "compressed stream not analyzable on this interpreter",
                    Severity.MEDIUM, Category.INTEGRITY, "(stream)",
                    detail="zstd support requires Python 3.14+ (compression.zstd).",
                    confidence="high",
                    remediation="Re-run on a newer interpreter, or decompress offline."))
                return None, findings
        else:
            return None, findings
    except Exception as exc:
        findings.append(Finding(
            "MLSC-ENG-002", f"Failed to decompress {fmt} stream",
            Severity.MEDIUM, Category.INTEGRITY, "(stream)",
            detail=str(exc), confidence="medium"))
        return None, findings

    if len(data) > 0 and len(raw) / max(len(data), 1) > BOMB_RATIO:
        findings.append(Finding(
            "MLSC-ZIP-003", "Extreme compression ratio (possible zip bomb)",
            Severity.MEDIUM, Category.INTEGRITY, "(stream)",
            detail=f"ratio {len(raw) / max(len(data), 1):.0f}:1 after {fmt} decompress",
            evidence=[f"{len(data)} -> {len(raw)} bytes"],
            confidence="medium",
            remediation="Cap extraction size; do not decompress untrusted archives in place."))
        return None, findings
    if len(raw) > MAX_DECOMPRESSED:
        findings.append(Finding(
            "MLSC-ENG-001", "Decompressed payload exceeds size limit",
            Severity.MEDIUM, Category.INTEGRITY, "(stream)",
            detail=f"{len(raw)} bytes > {MAX_DECOMPRESSED} byte cap",
            confidence="medium"))
        return None, findings
    return raw, findings


def _scan_tar(path: Path, display: str) -> list[Finding]:
    """Inspect tar members without extracting to disk."""
    out: list[Finding] = []
    try:
        with tarfile.open(path, "r:*") as tf:
            for m in tf.getmembers():
                name = m.name
                if name.startswith("/") or ".." in Path(name).parts:
                    out.append(Finding(
                        "MLSC-ZIP-001", "Tar entry escapes the extraction directory",
                        Severity.CRITICAL, Category.FILE_ANOMALY, f"{display}!{name}",
                        detail="Archive member uses an absolute path or `..` traversal.",
                        evidence=[name], remediation="Do not extract. Reject the artifact."))
                mode = m.mode or 0
                if m.isfile() and (mode & 0o111):
                    out.append(Finding(
                        "MLSC-ZIP-006",
                        "Executable member bundled in tar archive",
                        Severity.HIGH, Category.FILE_ANOMALY, f"{display}!{name}",
                        detail="Weight archives should contain tensors and metadata only.",
                        evidence=[f"mode={oct(mode)}"], remediation="Inspect; treat as untrusted."))
                if m.isfile() and m.size <= MAX_DECOMPRESSED:
                    try:
                        fobj = tf.extractfile(m)
                        if fobj is None:
                            continue
                        blob = fobj.read(MAX_DECOMPRESSED + 1)
                        if len(blob) > MAX_DECOMPRESSED:
                            continue
                        if blob[:1] == b"\x80":
                            out.extend(pickle_scan.scan_pickle_blob(blob, f"{display}!{name}"))
                        elif blob[:6] == b"\x93NUMPY":
                            out.extend(formats.scan_npy_bytes(blob, f"{display}!{name}"))
                    except Exception as exc:
                        out.append(Finding(
                            "MLSC-ZIP-005", "Unreadable tar member",
                            Severity.LOW, Category.INTEGRITY, f"{display}!{name}",
                            detail=str(exc)))
    except tarfile.TarError as exc:
        out.append(Finding(
            "MLSC-ZIP-000", "Corrupt tar container",
            Severity.MEDIUM, Category.INTEGRITY, display, detail=str(exc)))
    return out


def scan_file(path: Path, display: str) -> list[Finding]:
    """Dispatch a single file to the appropriate analyser(s)."""
    fmt = classify(path)
    out: list[Finding] = []

    # Compressed wrappers (e.g. joblib gzip) — decompress then re-dispatch.
    if fmt in {"gzip", "bzip2", "xz", "zstd"}:
        try:
            data = path.read_bytes()
        except OSError as exc:
            return [Finding("MLSC-ENG-002", "Unreadable compressed file",
                            Severity.MEDIUM, Category.INTEGRITY, display, detail=str(exc))]
        if len(data) > MAX_DECOMPRESSED:
            return [Finding("MLSC-ENG-001", "Compressed file exceeds read limit",
                            Severity.MEDIUM, Category.INTEGRITY, display,
                            detail=f"{len(data)} bytes")]
        raw, dec_findings = _decompress(data, fmt)
        for f in dec_findings:
            f.location = display
            out.append(f)
        if raw is None:
            return out
        inner = magic_label(raw[:16])
        if raw[:1] == b"\x80" or inner.startswith("pickle"):
            out.extend(pickle_scan.scan_pickle_blob(raw, display))
        elif raw[:6] == b"\x93NUMPY":
            out.extend(formats.scan_npy_bytes(raw, display))
        elif raw[:2] == b"PK":
            out.append(Finding(
                "MLSC-ENG-004", "Compressed ZIP stream requires manual extraction",
                Severity.MEDIUM, Category.INTEGRITY, display,
                detail=f"Inner content looks like a ZIP after {fmt} decompress.",
                confidence="medium", remediation="Decompress offline and re-scan the archive."))
        elif len(raw) >= 262 and raw[257:262] == b"ustar":
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".tar", delete=True) as tmp:
                tmp.write(raw)
                tmp.flush()
                out.extend(_scan_tar(Path(tmp.name), display))
        else:
            out.append(Finding(
                "MLSC-ENG-004", f"Decompressed {fmt} content not a recognised model format",
                Severity.LOW, Category.INTEGRITY, display,
                detail=f"inner magic={inner!r}", confidence="medium"))
        return out

    if fmt == "tar" or (fmt not in {"gzip", "bzip2", "xz", "zstd"} and tarfile.is_tarfile(path)):
        return _scan_tar(path, display)

    head = sniff(path, 300)
    if len(head) >= 262 and head[257:262] in (b"ustar", b"ustar\x00")[:5]:
        return _scan_tar(path, display)

    if fmt == "pickle":
        out += pickle_scan.scan_pickle_file(path, display)
    elif fmt in {"torch-zip", "zip", "keras-v3"}:
        out += formats.scan_zip_archive(path, display)
    elif fmt == "safetensors":
        out += formats.scan_safetensors(path, display)
    elif fmt == "npy":
        out += formats.scan_npy(path, display)
    elif fmt == "npz":
        out += formats.scan_npz(path, display)
    elif fmt == "hdf5":
        out += formats.scan_hdf5(path, display)
    elif fmt == "onnx":
        out += formats.scan_onnx(path, display)
    elif fmt == "tf-protobuf":
        out += formats.scan_tf_protobuf(path, display)
    elif fmt == "gguf":
        out += formats.scan_gguf(path, display)
    elif fmt == "python-source":
        out += metadata.scan_python_source(path, display)
    elif fmt == "notebook":
        out += metadata.scan_notebook(path, display)
    elif fmt == "git-lfs-pointer":
        out.append(Finding(
            "MLSC-LFS-001", "Git LFS pointer scanned instead of real bytes",
            Severity.LOW, Category.FILE_ANOMALY, display,
            detail=("This file is a Git LFS pointer stub (~130 bytes of text). The "
                    "real weight bytes were never fetched, so a clean scan here is "
                    "meaningless. Enable `lfs: true` in CI / run `git lfs pull`."),
            evidence=["detected format: git-lfs-pointer"],
            remediation="Fetch LFS objects before scanning.",
            confidence="high"))

    if path.name == "config.json":
        out += metadata.scan_config_json(path, display)

    if fmt in UNEXPECTED_FORMATS:
        sev, why = UNEXPECTED_FORMATS[fmt]
        out.append(Finding(
            "MLSC-FILE-001", f"Unexpected file type in model repository ({why})",
            sev, Category.FILE_ANOMALY, display,
            detail=("Model repositories should contain weights, tokenizer assets and "
                    "text metadata. Native binaries and scripts are out of scope for "
                    "a weights distribution channel."),
            evidence=[f"detected format: {fmt}"],
            remediation="Inspect the file; treat the repository as untrusted."))

    ext = path.suffix.lower()
    if ext in EXT_MAGIC_EXPECT and fmt not in EXT_MAGIC_EXPECT[ext] and fmt != "unknown":
        out.append(Finding(
            "MLSC-FILE-002", f"File content does not match its extension ({ext})",
            Severity.HIGH, Category.FILE_ANOMALY, display,
            detail=("The magic bytes indicate a different format than the extension "
                    "advertises. Masquerading a pickle as `.safetensors` defeats "
                    "naive `use_safetensors=True` safety assumptions."),
            evidence=[f"extension {ext} but detected {fmt}"],
            remediation="Reject the file."))
    return out


def scan_local(root: Path, hash_files: bool = False,
               max_file_mb: int = 4096, jobs: int = 1,
               only: set[str] | None = None,
               skip: set[str] | None = None,
               repo_id: str | None = None,
               online: bool = False,
               hf_token: str | None = None) -> ScanResult:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    root = root.resolve()
    target = ScanTarget(kind="local", identifier=str(root))
    result = ScanResult(target=target)

    if online and not repo_id:
        result.errors.append("--online has no effect without --repo-id")

    if root.is_file():
        paths = [root]
        base = root.parent
    else:
        paths = walk_files(root)
        base = root

    def _one(p: Path) -> tuple[str, FileRecord, list[Finding], str | None]:
        try:
            size = p.stat().st_size
        except OSError as exc:
            return str(p), FileRecord(path=p.name, size=0), [], f"{p}: {exc}"
        rel = str(p.relative_to(base)) if base in p.parents or base == p.parent else p.name
        fmt = classify(p)
        rec = FileRecord(path=rel, size=size, format=fmt)
        if size > max_file_mb * 1024 * 1024:
            return rel, rec, [], f"{rel}: skipped, {size} bytes exceeds limit"
        findings: list[Finding] = []
        err = None
        try:
            findings = scan_file(p, rel)
            findings = _filter_analyzers(findings, only, skip)
            rec.inspected = True
            if hash_files and size < 512 * 1024 * 1024:
                rec.sha256 = sha256_file(p)
        except Exception as exc:
            err = f"{rel}: {type(exc).__name__}: {exc}"
        return rel, rec, findings, err

    n_jobs = max(1, jobs)
    collected: list[tuple[str, FileRecord, list[Finding], str | None]] = []
    if n_jobs == 1:
        for p in sorted(paths):
            collected.append(_one(p))
    else:
        with ThreadPoolExecutor(max_workers=n_jobs) as pool:
            futs = {pool.submit(_one, p): p for p in paths}
            for fut in as_completed(futs):
                collected.append(fut.result())

    collected.sort(key=lambda t: t[0])
    for _rel, rec, findings, err in collected:
        result.files.append(rec)
        for f in findings:
            result.add(f)
        if err:
            result.errors.append(err)

    if root.is_dir():
        if _analyzer_enabled("metadata", only, skip) or _analyzer_enabled("repo_hygiene", only, skip):
            for f in metadata.scan_repo_consistency(root, paths):
                result.add(f)
        if _analyzer_enabled("templates", only, skip):
            from . import templates
            for f in templates.analyze_templates(root, paths):
                result.add(f)
        if _analyzer_enabled("provenance", only, skip):
            from . import provenance
            for f in provenance.scan_provenance(root, paths):
                result.add(f)

    if repo_id and _analyzer_enabled("typosquat", only, skip):
        from .data.popular import corpus_metadata, load_refreshed_corpus
        corpus = load_refreshed_corpus()
        result.remote_metadata.update(corpus_metadata(corpus))
        if corpus.error:
            result.errors.append(corpus.error)
        for f in typosquat.check_identifier(repo_id):
            result.add(f)

        if online:
            try:
                info = hub.fetch_repo_info(repo_id, token=hf_token)
            except Exception as exc:
                result.errors.append(
                    f"hub metadata unavailable: {type(exc).__name__}: {exc}")
            else:
                result.remote_metadata.update({
                    k: info.get(k) for k in
                    ("id", "author", "downloads", "likes", "createdAt",
                     "lastModified", "gated", "disabled", "library_name",
                     "pipeline_tag")
                })
                for f in hub.provenance_findings(repo_id, info):
                    result.add(f)
                siblings = [s.get("rfilename")
                            for s in (info.get("siblings") or []) if s.get("rfilename")]
                if siblings:
                    for f in hub.local_vs_remote(
                            siblings, [r.path for r in result.files]):
                        result.add(f)

    result.findings.sort(key=lambda f: (f.severity.rank, f.rule_id, f.location, f.title),
                         reverse=True)
    result.finished_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
    return result


def _analyzer_enabled(name: str, only: set[str] | None, skip: set[str] | None) -> bool:
    if only is not None and name not in only:
        return False
    if skip is not None and name in skip:
        return False
    return True


def _filter_analyzers(findings: list[Finding], only: set[str] | None,
                      skip: set[str] | None) -> list[Finding]:
    """Map rule prefixes to analyzer names for --only/--skip."""
    if only is None and skip is None:
        return findings
    prefix_map = {
        "MLSC-PKL": "pickle_scan", "MLSC-FMT": "pickle_scan",
        "MLSC-ZIP": "containers", "MLSC-KRS": "containers",
        "MLSC-STF": "formats", "MLSC-NPY": "formats", "MLSC-GGUF": "formats",
        "MLSC-ONX": "formats", "MLSC-TF": "formats", "MLSC-H5": "formats",
        "MLSC-CFG": "repo_hygiene", "MLSC-PY": "pysource", "MLSC-NB": "repo_hygiene",
        "MLSC-REPO": "repo_hygiene", "MLSC-TPL": "templates",
        "MLSC-FILE": "engine", "MLSC-ENG": "engine", "MLSC-LFS": "engine",
        "MLSC-SIG": "provenance", "MLSC-SQT": "typosquat", "MLSC-PRV": "hfhub",
    }

    def analyzer_for(rid: str) -> str:
        for pref, name in prefix_map.items():
            if rid.startswith(pref):
                return name
        return "engine"

    out = []
    for f in findings:
        name = analyzer_for(f.rule_id)
        if only is not None and name not in only:
            continue
        if skip is not None and name in skip:
            continue
        out.append(f)
    return out


def scan_hub(repo_id: str, revision: str = "main", token: str | None = None,
             deep: bool = True, max_remote_members: int = 6) -> ScanResult:
    """Metadata + name analysis, plus optional range-read pickle extraction."""
    from .data.popular import corpus_metadata, load_refreshed_corpus

    target = ScanTarget(kind="hub", identifier=repo_id, revision=revision)
    result = ScanResult(target=target)

    corpus = load_refreshed_corpus()
    result.remote_metadata.update(corpus_metadata(corpus))
    if corpus.error:
        result.errors.append(corpus.error)

    for f in typosquat.check_identifier(repo_id):
        result.add(f)

    try:
        info = hub.fetch_repo_info(repo_id, token=token)
    except Exception as exc:
        result.errors.append(f"hub metadata unavailable: {type(exc).__name__}: {exc}")
        result.finished_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
        return result

    target.metadata = {k: info.get(k) for k in
                       ("id", "author", "downloads", "likes", "createdAt",
                        "lastModified", "gated", "disabled", "library_name", "pipeline_tag")}
    for f in hub.provenance_findings(repo_id, info):
        result.add(f)

    files = hub.repo_files(info)
    for rf in files:
        result.files.append(FileRecord(path=rf.path, size=rf.size or 0,
                                       format=_ext_format(rf.path)))

    names = [f.path for f in files]
    has_st = any(n.endswith(".safetensors") for n in names)
    pickles = [n for n in names if n.endswith((".bin", ".pt", ".pth", ".ckpt", ".pkl"))]
    py = [n for n in names if n.endswith(".py")]

    if pickles and not has_st:
        result.add(Finding(
            "MLSC-REPO-001", "Weights available only in pickle-based format",
            Severity.MEDIUM, Category.SERIALIZATION, repo_id,
            detail="No safetensors sibling; consumers are forced onto the unsafe load path.",
            evidence=pickles[:8],
            remediation="Prefer a repo that publishes safetensors."))
    if py:
        result.add(Finding(
            "MLSC-REPO-006", "Repository ships Python modules",
            Severity.MEDIUM, Category.EXECUTION, repo_id,
            detail="These execute if the model is loaded with trust_remote_code=True.",
            evidence=py[:8], remediation="Review each file before loading."))

    if deep:
        if "config.json" in names:
            try:
                blob = hub._get(hub.resolve_url(repo_id, "config.json", revision))
                import json as _json
                cfg = _json.loads(blob)
                if "auto_map" in cfg:
                    result.add(Finding(
                        "MLSC-CFG-001",
                        "config.json declares `auto_map` (requires trust_remote_code)",
                        Severity.HIGH, Category.EXECUTION, f"{repo_id}/config.json",
                        detail="transformers will import and execute repo-local Python.",
                        evidence=[_json.dumps(cfg["auto_map"])[:400]],
                        remediation="Read the referenced modules or refuse trust_remote_code."))
            except Exception as exc:
                result.errors.append(f"config.json: {exc}")

        for name in pickles[:max_remote_members]:
            url = hub.resolve_url(repo_id, name, revision)
            try:
                rz = hub.RemoteZip(url).open()
                members = [e.name for e in rz.entries
                           if e.name.endswith((".pkl", ".pickle"))]
                if not members:
                    continue
                for m in members[:3]:
                    blob = rz.read(m)
                    for f in pickle_scan.scan_pickle_blob(blob, f"{name}!{m}"):
                        result.add(f)
            except Exception as exc:
                # Legacy (non-zip) torch files: grab the first 2MB instead.
                try:
                    import urllib.request
                    req = urllib.request.Request(
                        url, headers={"User-Agent": hub.UA, "Range": "bytes=0-2097151"})
                    with urllib.request.urlopen(req, timeout=60) as r:
                        head = r.read()
                    if head[:1] == b"\x80":
                        for f in pickle_scan.scan_pickle_blob(head, name):
                            result.add(f)
                    else:
                        result.errors.append(f"{name}: remote inspection failed ({exc})")
                except Exception as exc2:
                    result.errors.append(f"{name}: remote inspection failed ({exc2})")

    result.finished_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
    return result


def _ext_format(name: str) -> str:
    ext = Path(name).suffix.lower()
    return {".safetensors": "safetensors", ".bin": "pickle", ".pt": "pickle",
            ".pth": "pickle", ".ckpt": "pickle", ".gguf": "gguf",
            ".onnx": "onnx", ".py": "python-source", ".json": "text",
            ".md": "text"}.get(ext, "unknown")
