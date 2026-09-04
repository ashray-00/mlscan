"""Hugging Face Hub access.

Two capabilities:

1. Repo metadata (siblings, downloads, timestamps, gating) via the public API.
2. `RemoteZip` -- reads a torch `.bin` archive's central directory and a single
   member over HTTP Range requests. This lets us extract and analyse the
   ~50KB `data.pkl` out of a 70GB shard **without downloading the weights**.
   That property is what makes the scanner usable as a pre-download gate.
"""
from __future__ import annotations

import json
import struct
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from pathlib import Path

from .findings import Category, Finding, Severity

HF_API = "https://huggingface.co/api"
UA = "mlscan/0.1 (+defensive model supply-chain scanner)"

EOCD_SIG = b"PK\x05\x06"
EOCD64_SIG = b"PK\x06\x06"
EOCD64_LOC_SIG = b"PK\x06\x07"
CD_SIG = b"PK\x01\x02"
LFH_SIG = b"PK\x03\x04"


def _get(url: str, headers: dict[str, str] | None = None, timeout: int = 30) -> bytes:
    """GET with exponential backoff. Cap at 3 attempts; honour Retry-After on 429.

    Network failure must never change a verdict — callers catch errors and
    degrade to "no reputation data" plus a `report.errors` note.
    """
    import time
    last_exc: Exception | None = None
    for attempt in range(3):
        req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            last_exc = exc
            if exc.code == 429:
                retry_after = exc.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else (2 ** attempt)
                except ValueError:
                    delay = 2 ** attempt
                time.sleep(min(delay, 30))
                continue
            if exc.code >= 500 and attempt < 2:
                time.sleep(2 ** attempt)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_exc = exc
            if attempt < 2:
                time.sleep(2 ** attempt)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def fetch_author_models(author: str, token: str | None = None,
                        limit: int = 100) -> list[dict[str, Any]]:
    """List models published by a hub account (bulk-upload signal)."""
    url = f"{HF_API}/models?author={urllib.parse.quote(author)}&limit={limit}&sort=createdAt&direction=-1"
    hdrs = {"Authorization": f"Bearer {token}"} if token else {}
    return json.loads(_get(url, hdrs))


def _head(url: str, timeout: int = 30):
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    return urllib.request.urlopen(req, timeout=timeout)


def fetch_repo_info(repo_id: str, kind: str = "models", token: str | None = None) -> dict[str, Any]:
    url = f"{HF_API}/{kind}/{repo_id}"
    hdrs = {"Authorization": f"Bearer {token}"} if token else {}
    return json.loads(_get(url, hdrs))

@dataclass
class RepoFile:
    path: str
    size: int | None = None
    lfs: bool = False


def repo_files(info: dict[str, Any]) -> list[RepoFile]:
    out = []
    for s in info.get("siblings", []) or []:
        out.append(RepoFile(path=s.get("rfilename", ""),
                            size=s.get("size"),
                            lfs=bool(s.get("lfs"))))
    return out


def resolve_url(repo_id: str, filename: str, revision: str = "main") -> str:
    return f"https://huggingface.co/{repo_id}/resolve/{revision}/{filename}"


def provenance_findings(repo_id: str, info: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    downloads = info.get("downloads") or 0
    likes = info.get("likes") or 0
    created = info.get("createdAt") or info.get("lastModified")

    age_days = None
    if created:
        try:
            dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - dt).days
        except Exception:
            pass

    if age_days is not None and age_days < 14:
        out.append(Finding(
            "MLSC-PRV-001", "Repository created very recently",
            Severity.LOW, Category.PROVENANCE, repo_id,
            detail=f"created ~{age_days} day(s) ago; no community review history yet",
            evidence=[str(created)], confidence="medium"))
    if downloads < 100 and likes < 5:
        out.append(Finding(
            "MLSC-PRV-002", "Low adoption signal",
            Severity.LOW, Category.PROVENANCE, repo_id,
            detail=f"downloads={downloads}, likes={likes}. Weak herd-immunity evidence.",
            confidence="low",
            remediation="Weight other findings more heavily for unpopular repos."))
    if info.get("gated"):
        out.append(Finding(
            "MLSC-PRV-003", "Repository is gated",
            Severity.INFO, Category.PROVENANCE, repo_id,
            detail="Gating implies an accountable publisher, a mild positive signal.",
            confidence="low"))
    if info.get("disabled"):
        out.append(Finding(
            "MLSC-PRV-004", "Repository is flagged/disabled by the hub",
            Severity.HIGH, Category.PROVENANCE, repo_id,
            detail="The hub has disabled this repo, often after an abuse report.",
            remediation="Do not use."))
    tags = set(info.get("tags") or [])
    if "custom_code" in tags:
        out.append(Finding(
            "MLSC-PRV-005", "Hub marks this repo as containing custom code",
            Severity.MEDIUM, Category.EXECUTION, repo_id,
            detail="`custom_code` means loading requires trust_remote_code=True.",
            remediation="Review all bundled .py files before loading."))

    # Bulk-upload signal: brand-new account that already has many repos.
    author = info.get("author") or (repo_id.split("/", 1)[0] if "/" in repo_id else None)
    if author and age_days is not None and age_days < 30:
        try:
            siblings = fetch_author_models(author, limit=50)
            n = len(siblings)
            if n >= 10:
                out.append(Finding(
                    "MLSC-PRV-006",
                    f"Publisher account has {n}+ repositories, created within {age_days} days",
                    Severity.MEDIUM, Category.PROVENANCE, repo_id,
                    detail=("A young account that already publishes many repositories is a "
                            "common bulk-upload / squat pattern. Correlational only."),
                    evidence=[f"author={author}", f"listed_models≈{n}", f"age_days={age_days}"],
                    confidence="low",
                    remediation="Prefer well-known namespaces; verify the publisher identity."))
        except Exception:
            # Network failure must not change the verdict — degrade silently here;
            # the caller already records hub errors when fetch_repo_info fails.
            pass
    return out


def local_vs_remote(remote_names: list[str], local_paths: list[str]) -> list[Finding]:
    """Files present locally but absent upstream = injected after download."""
    remote = set(remote_names)
    # Ignore local-only docs noise; focus on weight-like and code paths.
    interesting = []
    for p in local_paths:
        base = Path(p).name
        if base in {"README.md", ".gitattributes", ".gitignore"}:
            continue
        if p not in remote and base not in remote:
            interesting.append(p)
    if not interesting:
        return []
    return [Finding(
        "MLSC-PRV-007",
        "Local files not listed in hub manifest",
        Severity.HIGH, Category.PROVENANCE, interesting[0],
        detail=("These paths exist in the local tree but are absent from the hub "
                "siblings list. Either the copy was modified after download, or it "
                "did not come from the claimed repository."),
        evidence=interesting[:12],
        confidence="medium",
        remediation="Re-download from the hub and re-scan, or treat as untrusted.")]

@dataclass
class RemoteEntry:
    name: str
    method: int
    comp_size: int
    uncomp_size: int
    header_offset: int
    external_attr: int = 0


class RemoteZipError(RuntimeError):
    pass

@dataclass
class RemoteZip:
    url: str
    size: int = 0
    entries: list[RemoteEntry] = field(default_factory=list)
    _final_url: str = ""

    def _range(self, start: int, end: int) -> bytes:
        """Inclusive byte range."""
        req = urllib.request.Request(
            self._final_url or self.url,
            headers={"User-Agent": UA, "Range": f"bytes={start}-{end}"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            if resp.status not in (206, 200):
                raise RemoteZipError(f"server ignored Range (status {resp.status})")
            return resp.read()

    def open(self) -> "RemoteZip":
        resp = _head(self.url)
        self._final_url = resp.url          # follow LFS/CDN redirect
        self.size = int(resp.headers.get("Content-Length") or 0)
        if self.size <= 0:
            raise RemoteZipError("no Content-Length; cannot range-read")
        self._read_central_directory()
        return self

    def _read_central_directory(self) -> None:
        tail_len = min(self.size, 65_557)
        tail = self._range(self.size - tail_len, self.size - 1)
        idx = tail.rfind(EOCD_SIG)
        if idx < 0:
            raise RemoteZipError("EOCD record not found (not a zip?)")
        (_, _, _, _, cd_count, cd_size, cd_off, _) = struct.unpack_from(
            "<4sHHHHIIH", tail, idx)

        # zip64 (torch shards > 4GB)
        if cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF or cd_count == 0xFFFF:
            loc = tail.rfind(EOCD64_LOC_SIG)
            if loc < 0:
                raise RemoteZipError("zip64 locator missing")
            _, _, eocd64_off, _ = struct.unpack_from("<4sIQI", tail, loc)
            rec = self._range(eocd64_off, eocd64_off + 55)
            if rec[:4] != EOCD64_SIG:
                raise RemoteZipError("bad zip64 EOCD record")
            cd_size = struct.unpack_from("<Q", rec, 40)[0]
            cd_off = struct.unpack_from("<Q", rec, 48)[0]

        cd = self._range(cd_off, cd_off + cd_size - 1)
        pos = 0
        while pos + 46 <= len(cd) and cd[pos:pos + 4] == CD_SIG:
            (_sig, _vmb, _vn, _flags, method, _t, _d, _crc, csize, usize,
             nlen, elen, clen, _disk, _ia, ext_attr, lho) = struct.unpack_from(
                "<4sHHHHHHIIIHHHHHII", cd, pos)
            name = cd[pos + 46: pos + 46 + nlen].decode("utf-8", "replace")
            # zip64 extra field overrides
            if usize == 0xFFFFFFFF or csize == 0xFFFFFFFF or lho == 0xFFFFFFFF:
                extra = cd[pos + 46 + nlen: pos + 46 + nlen + elen]
                usize, csize, lho = _parse_zip64_extra(extra, usize, csize, lho)
            self.entries.append(RemoteEntry(name, method, csize, usize, lho, ext_attr))
            pos += 46 + nlen + elen + clen

    def read(self, name: str, max_bytes: int = 32 * 1024 * 1024) -> bytes:
        ent = next((e for e in self.entries if e.name == name), None)
        if ent is None:
            raise KeyError(name)
        if ent.comp_size > max_bytes:
            raise RemoteZipError(f"member too large ({ent.comp_size} bytes)")
        lfh = self._range(ent.header_offset, ent.header_offset + 29)
        if lfh[:4] != LFH_SIG:
            raise RemoteZipError("bad local file header")
        nlen, elen = struct.unpack_from("<HH", lfh, 26)
        start = ent.header_offset + 30 + nlen + elen
        blob = self._range(start, start + ent.comp_size - 1)
        if ent.method == 0:
            return blob
        if ent.method == 8:
            return zlib.decompress(blob, -zlib.MAX_WBITS)
        raise RemoteZipError(f"unsupported compression method {ent.method}")


def _parse_zip64_extra(extra: bytes, usize: int, csize: int, lho: int):
    pos = 0
    while pos + 4 <= len(extra):
        hid, hsz = struct.unpack_from("<HH", extra, pos)
        body = extra[pos + 4: pos + 4 + hsz]
        if hid == 0x0001:
            off = 0
            if usize == 0xFFFFFFFF and off + 8 <= len(body):
                usize = struct.unpack_from("<Q", body, off)[0]; off += 8
            if csize == 0xFFFFFFFF and off + 8 <= len(body):
                csize = struct.unpack_from("<Q", body, off)[0]; off += 8
            if lho == 0xFFFFFFFF and off + 8 <= len(body):
                lho = struct.unpack_from("<Q", body, off)[0]; off += 8
            break
        pos += 4 + hsz
    return usize, csize, lho
