"""Command-line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, report, scanner
from .findings import Severity
from .scoring import Policy, apply_policy, exit_code

# Keep in sync with LIMITATIONS.md at the repository root.
LIMITATIONS = """\
mlscan — known limits (see LIMITATIONS.md for the full write-up)

Detects (by prefix): pickle RCE gadgets and format abuse (MLSC-PKL/FMT);
archive Zip Slip, bombs, embedded executables (MLSC-ZIP); Keras Lambda /
custom objects (MLSC-KRS/H5); safetensors / npy / onnx / gguf / TF graph
anomalies (MLSC-STF/NPY/ONX/GGUF/TF); auto_map and bundled Python/notebooks
(MLSC-CFG/PY/NB/REPO); naming confusion and hub provenance (MLSC-SQT/PRV);
extension/content masquerade (MLSC-FILE); attestation inventory (MLSC-SIG).

Does NOT detect: backdoored weights (byte-normal safetensors trained to
misbehave on a trigger — a behavioural problem, not a format one); data
poisoning; encrypted or runtime-decrypted payloads; novel gadgets absent
from the denylist (surface as MLSC-PKL-002 MEDIUM, not CRITICAL); pickle
EXT opcode targets (flagged unresolvable, never pretended-resolved);
signature cryptographic validity (signatures are inventoried but not
verified — publishers largely do not sign models yet).

False positives: legitimate auto_map / custom code; benign reconstruction
helpers outside the allowlist; intentional republisher namespaces; brand-new
low-download repos; expected ONNX custom-op domains.

False negatives: Git LFS pointer stubs (real bytes never fetched); files
over the size limit; stale typosquat corpus; compression the interpreter
cannot open; gadgets requiring runtime state the static VM cannot rebuild.
"""

_ANALYZERS = [
    "pickle_scan", "containers", "formats", "repo_hygiene", "pysource",
    "templates", "typosquat", "hfhub", "provenance", "engine",
]


def load_policy(path: str | None) -> Policy:
    if not path:
        return Policy()
    text = Path(path).read_text()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # optional dependency
            return Policy.from_dict(yaml.safe_load(text))
        except ImportError:
            print("PyYAML not installed; use a .json policy file", file=sys.stderr)
            raise SystemExit(3)
    return Policy.from_dict(json.loads(text))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mlscan",
        description="Static supply-chain scanner for ML model artifacts.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a local path")
    s.add_argument("path")
    s.add_argument("-f", "--format", default="text",
                   choices=["text", "json", "sarif", "html", "cyclonedx"])
    s.add_argument("-o", "--output")
    s.add_argument("--policy")
    s.add_argument("--hash", action="store_true", help="record sha256 of each file")
    s.add_argument("--repo-id", help="hub ID to also run name checks against")
    s.add_argument("--online", action="store_true",
                   help="query the Hub API for reputation metadata (default: off)")
    s.add_argument("--hf-token", default=os.environ.get("HF_TOKEN"),
                   help="HF token (default: $HF_TOKEN)")
    s.add_argument("--baseline", metavar="PATH",
                   help="suppress findings unchanged since this JSON report")
    s.add_argument("--write-baseline", metavar="PATH",
                   help="write the (post-policy) JSON report as a new baseline")
    s.add_argument("--jobs", type=int, default=None,
                   help="parallel file workers (default: min(8, cpu_count))")
    s.add_argument("--only", action="append", choices=_ANALYZERS, default=None,
                   help="run only these analyzers (repeatable)")
    s.add_argument("--skip", action="append", choices=_ANALYZERS, default=None,
                   help="skip these analyzers (repeatable)")
    s.add_argument("--fail-on", default=None,
                   choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    s.add_argument("-v", "--verbose", action="store_true")
    s.add_argument("--no-color", action="store_true")

    h = sub.add_parser("hub", help="typosquat (+ optional reputation) for a hub ID")
    h.add_argument("repo_id")
    h.add_argument("--online", action="store_true",
                   help="query the Hub API for reputation metadata")
    h.add_argument("--revision", default="main")
    h.add_argument("--token")
    h.add_argument("--hf-token", default=os.environ.get("HF_TOKEN"))
    h.add_argument("--no-deep", action="store_true",
                   help="metadata + naming only; skip remote pickle extraction")
    h.add_argument("-f", "--format", default="text",
                   choices=["text", "json", "sarif", "html", "cyclonedx"])
    h.add_argument("-o", "--output")
    h.add_argument("--policy")
    h.add_argument("--fail-on", default=None,
                   choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"])
    h.add_argument("-v", "--verbose", action="store_true")
    h.add_argument("--no-color", action="store_true")

    n = sub.add_parser("name", help="alias for hub (typosquat check only offline)")
    n.add_argument("repo_id")

    e = sub.add_parser("explain", help="disassemble a pickle stream")
    e.add_argument("path")
    e.add_argument("--member", help="member name inside a zip archive")
    e.add_argument("--max-ops", type=int, default=200)

    r = sub.add_parser("refresh-corpus",
                       help="refresh typosquat reference corpus from the Hub")
    r.add_argument("--limit", type=int, default=1000,
                   help="number of top-download models to sample (default 1000)")
    r.add_argument("--token", help="optional HF token")

    sub.add_parser("limitations", help="print what mlscan does and does not detect")
    return p


def _cmd_refresh(limit: int, token: str | None) -> int:
    """Pull top-download model IDs and union authors/basenames into the corpus."""
    from .data.popular import SEED_MODELS, SEED_ORGS, write_refreshed_corpus
    from .hub import HF_API, _get

    orgs = set(SEED_ORGS)
    models = set(SEED_MODELS)
    url = f"{HF_API}/models?sort=downloads&direction=-1&limit={limit}&full=false"
    hdrs = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        blob = _get(url, hdrs, timeout=60)
        items = json.loads(blob)
    except Exception as exc:
        print(f"error: failed to refresh corpus: {exc}", file=sys.stderr)
        return 3
    if not isinstance(items, list):
        print("error: unexpected hub response shape", file=sys.stderr)
        return 3
    for it in items:
        rid = (it or {}).get("id") or ""
        if "/" not in rid:
            continue
        org, _, name = rid.partition("/")
        if org:
            orgs.add(org)
        if name:
            models.add(name.lower())
    path = write_refreshed_corpus(orgs, models)
    print(f"wrote {path} ({len(orgs)} orgs, {len(models)} models)")
    return 0


def _default_jobs() -> int:
    return min(8, os.cpu_count() or 1)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "explain":
        from .explain import explain
        explain(args.path, args.member, args.max_ops)
        return 0

    if args.cmd == "limitations":
        print(LIMITATIONS)
        return 0

    if args.cmd == "refresh-corpus":
        return _cmd_refresh(args.limit, args.token)

    if args.cmd == "name":
        from .typosquat import check_identifier
        fs = check_identifier(args.repo_id)
        if not fs:
            print(f"{args.repo_id}: no naming anomalies detected")
            return 0
        for f in fs:
            print(f"[{f.severity.value}] {f.rule_id} {f.title}")
            for e in f.evidence:
                print(f"    {e}")
        return 1

    policy = load_policy(getattr(args, "policy", None))
    if getattr(args, "fail_on", None):
        policy.fail_on = Severity(args.fail_on)

    if args.cmd == "scan":
        target = Path(args.path)
        if not target.exists():
            print(f"error: {target} does not exist", file=sys.stderr)
            return 3
        need_hash = args.hash or bool(args.baseline) or bool(args.write_baseline)
        only = set(args.only) if args.only else None
        skip = set(args.skip) if args.skip else None
        result = scanner.scan_local(
            target,
            hash_files=need_hash,
            jobs=args.jobs if args.jobs is not None else _default_jobs(),
            only=only,
            skip=skip,
            repo_id=args.repo_id,
            online=args.online,
            hf_token=args.hf_token,
        )
        if args.baseline:
            from .baseline import apply_baseline
            apply_baseline(result, Path(args.baseline))
    elif args.cmd == "hub":
        if not args.online:
            from .typosquat import check_identifier
            from .findings import ScanResult, ScanTarget
            from .data.popular import corpus_metadata, load_refreshed_corpus
            result = ScanResult(target=ScanTarget(kind="hub", identifier=args.repo_id))
            corpus = load_refreshed_corpus()
            result.remote_metadata.update(corpus_metadata(corpus))
            for f in check_identifier(args.repo_id):
                result.add(f)
        else:
            result = scanner.scan_hub(
                args.repo_id, revision=args.revision,
                token=args.token or args.hf_token,
                deep=not args.no_deep)
    else:
        print(f"error: unknown command {args.cmd}", file=sys.stderr)
        return 3

    apply_policy(result, policy)

    if args.cmd == "scan" and getattr(args, "write_baseline", None):
        from .baseline import write_baseline
        write_baseline(result, Path(args.write_baseline))
        print(f"wrote baseline {args.write_baseline}", file=sys.stderr)

    if args.format == "json":
        text = report.render_json(result)
    elif args.format == "sarif":
        text = report.render_sarif(result)
    elif args.format == "html":
        text = report.render_html(result)
    elif args.format == "cyclonedx":
        text = report.render_cyclonedx(result)
    else:
        text = report.render_text(result, color=not args.no_color, verbose=args.verbose)

    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(text)
    return exit_code(result, policy)

if __name__ == "__main__":
    raise SystemExit(main())
