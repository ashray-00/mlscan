"""Signature / attestation inventory (not cryptographic verification).

Inventories known attestation filenames and reports when they are
present-but-unverified or absent. Cryptographic verify is deferred until
publisher signing is common enough to gate on without drowning in noise.
"""
from __future__ import annotations

from pathlib import Path

from .findings import Category, Finding, Severity

ANALYZER = "provenance"

SIG_SUFFIXES = (".sig", ".sigstore", ".intoto.jsonl")
SIG_NAMES = {"model.safetensors.sig"}
WELL_KNOWN = ".well-known"


def scan_provenance(root: Path, files: list[Path]) -> list[Finding]:
    """Inventory attestation artifacts beside weights. Does not verify them."""
    out: list[Finding] = []
    rels = []
    for f in files:
        try:
            rels.append(str(f.relative_to(root)))
        except ValueError:
            rels.append(f.name)

    has_weights = any(
        r.endswith((".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".gguf",
                    ".onnx", ".h5", ".npz"))
        for r in rels)
    sigs = []
    for r in rels:
        name = Path(r).name
        if name in SIG_NAMES or name.endswith(SIG_SUFFIXES) or WELL_KNOWN in Path(r).parts:
            sigs.append(r)

    if sigs:
        out.append(Finding(
            "MLSC-SIG-001",
            "Signatures/attestations present but unverified",
            Severity.INFO, Category.PROVENANCE, str(root),
            detail=("Found attestation artifacts, but mlscan does not yet perform "
                    "cryptographic verification. Treat presence as inventory only — "
                    "confirm the signature offline against a pinned publisher identity."),
            evidence=sigs[:8],
            confidence="high",
            remediation="Verify signatures offline against a pinned publisher identity "
                        "(Sigstore / in-toto / publisher-native)."))
    elif has_weights:
        out.append(Finding(
            "MLSC-SIG-002",
            "Weights ship with no attestation of any kind",
            Severity.INFO, Category.PROVENANCE, str(root),
            detail=("No `.sig`, `.sigstore`, `.intoto.jsonl`, or `.well-known` attestation "
                    "was found next to the weights. Unsigned model distribution is still "
                    "the norm; this is context, not a blocker."),
            confidence="high",
            remediation="Prefer publishers that sign releases once signing is available."))
    return out
