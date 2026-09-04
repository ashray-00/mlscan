"""Report renderers: terminal text, JSON, SARIF 2.1.0, and standalone HTML."""
from __future__ import annotations

import html
import json
from collections import Counter

from .findings import ScanResult, Severity

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
COLOR = {"CRITICAL": "\033[1;97;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[1;33m",
         "LOW": "\033[36m", "INFO": "\033[90m"}
RESET = "\033[0m"
VERDICT_COLOR = {"BLOCK": "\033[1;97;41m", "REVIEW": "\033[1;33m", "ALLOW": "\033[1;32m"}


def render_text(result: ScanResult, color: bool = True, verbose: bool = False) -> str:
    def c(code: str, s: str) -> str:
        return f"{code}{s}{RESET}" if color else s

    lines: list[str] = []
    t = result.target
    lines.append("=" * 78)
    lines.append(f" ML SUPPLY-CHAIN SCAN  ·  {t.identifier}")
    lines.append(f" target type: {t.kind}"
                 + (f"  ·  revision: {t.revision}" if t.revision else ""))
    lines.append("=" * 78)

    counts = result.counts()
    vc = VERDICT_COLOR.get(result.verdict.split()[0], "")
    lines.append("")
    lines.append(f" VERDICT: {c(vc, ' ' + result.verdict + ' ')}"
                 f"   risk score: {result.risk_score}/100")
    lines.append(" " + "  ".join(
        f"{c(COLOR[s.value], s.value)}={counts[s.value]}" for s in SEV_ORDER))
    lines.append("")

    fmt_counts = Counter(f.format for f in result.files)
    if fmt_counts:
        lines.append(f" files inspected: {sum(1 for f in result.files if f.inspected)}"
                     f"/{len(result.files)}")
        lines.append(" formats: " + ", ".join(
            f"{k}×{v}" for k, v in fmt_counts.most_common(10)))
        lines.append("")

    if not result.findings:
        lines.append(" No findings.")
    for sev in SEV_ORDER:
        group = [f for f in result.findings if f.severity is sev]
        if not group:
            continue
        if not verbose and sev is Severity.INFO:
            lines.append(f" [{sev.value}] {len(group)} informational finding(s) hidden (-v to show)")
            continue
        lines.append(c(COLOR[sev.value], f" ── {sev.value} ({len(group)}) " + "─" * 40))
        for f in group:
            new = " [NEW]" if f.is_new else ""
            lines.append(f"  [{f.rule_id}]{new} {f.title}")
            lines.append(f"      location : {f.location}")
            if f.detail:
                for chunk in _wrap(f.detail, 66):
                    lines.append(f"      {chunk}")
            for e in f.evidence[:4]:
                lines.append(f"      evidence : {e[:150]}")
            if f.confidence != "high":
                lines.append(f"      confidence: {f.confidence}")
            if f.remediation:
                lines.append(f"      fix      : {f.remediation}")
            lines.append("")

    if result.errors:
        lines.append(" ── SCAN ERRORS " + "─" * 46)
        for e in result.errors[:15]:
            lines.append(f"   ! {e}")
    lines.append("=" * 78)
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words, out, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            out.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        out.append(cur)
    return out


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_cyclonedx(result: ScanResult) -> str:
    """CycloneDX 1.6 JSON ML-BOM. Rule IDs are vulnerability ids — no invented CVEs."""
    import uuid
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bom_ref_model = f"model:{result.target.identifier}"
    components = [{
        "type": "machine-learning-model",
        "bom-ref": bom_ref_model,
        "name": result.target.identifier,
        "version": result.target.revision or "unknown",
    }]
    for fr in result.files:
        comp: dict = {
            "type": "file",
            "bom-ref": f"file:{fr.path}",
            "name": fr.path,
        }
        if fr.sha256:
            comp["hashes"] = [{"alg": "SHA-256", "content": fr.sha256}]
        components.append(comp)

    sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
               "LOW": "low", "INFO": "info"}
    vulns = [{
        "id": f.rule_id,
        "bom-ref": f"finding:{f.rule_id}:{f.location}",
        "source": {"name": "mlscan"},
        "description": f.title + (f" — {f.detail}" if f.detail else ""),
        "ratings": [{
            "source": {"name": "mlscan"},
            "severity": sev_map.get(f.severity.value, "unknown"),
            "method": "other",
        }],
        "affects": [{"ref": f"file:{f.location.split('!', 1)[0]}"}],
    } for f in result.findings]

    return json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": {"components": [{
                "type": "application",
                "name": "mlscan",
                "version": result.scanner_version,
            }]},
            "component": {
                "type": "machine-learning-model",
                "bom-ref": bom_ref_model,
                "name": result.target.identifier,
            },
        },
        "components": components,
        "vulnerabilities": vulns,
    }, indent=2)

SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
               "LOW": "note", "INFO": "note"}


def render_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 -- ingested natively by GitHub code scanning, Azure DevOps, etc."""
    rules, seen = [], set()
    for f in result.findings:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        rules.append({
            "id": f.rule_id,
            "name": f.rule_id.replace("-", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.detail or f.title},
            "help": {"text": f.remediation or "See detail."},
            "properties": {"category": f.category.value,
                           "security-severity": _sec_sev(f.severity)},
        })
    results = [{
        "ruleId": f.rule_id,
        "level": SARIF_LEVEL[f.severity.value],
        "message": {"text": f"{f.title} — {f.detail}"[:2000]},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.location.split("!")[0]}}}],
        "properties": {"evidence": f.evidence, "confidence": f.confidence,
                       "severity": f.severity.value},
    } for f in result.findings]

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "mlscan",
                "fullName": "ML Supply-Chain Analyzer",
                "version": result.scanner_version,
                "informationUri": "https://example.invalid/mlscan",
                "rules": rules}},
            "results": results,
            "invocations": [{
                "executionSuccessful": not result.errors,
                "toolExecutionNotifications": [
                    {"level": "error", "message": {"text": e}} for e in result.errors],
            }],
        }],
    }, indent=2)


def _sec_sev(sev: Severity) -> str:
    return {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0",
            "LOW": "3.0", "INFO": "0.0"}[sev.value]


def render_html(result: ScanResult) -> str:
    e = html.escape
    counts = result.counts()
    verdict = result.verdict.split()[0]
    vcol = {"BLOCK": "#b3261e", "REVIEW": "#a16207", "ALLOW": "#166534"}.get(verdict, "#334155")
    sevcol = {"CRITICAL": "#b3261e", "HIGH": "#c2410c", "MEDIUM": "#a16207",
              "LOW": "#0369a1", "INFO": "#64748b"}

    cards = []
    for sev in SEV_ORDER:
        for f in [x for x in result.findings if x.severity is sev]:
            ev = "".join(f"<li><code>{e(x[:300])}</code></li>" for x in f.evidence[:6])
            cards.append(f"""
    <article class="finding" style="border-left-color:{sevcol[sev.value]}">
      <header>
        <span class="badge" style="background:{sevcol[sev.value]}">{sev.value}</span>
        <span class="rule">{e(f.rule_id)}</span>
        <h3>{e(f.title)}</h3>
      </header>
      <p class="loc"><strong>Location:</strong> <code>{e(f.location)}</code>
         &nbsp;·&nbsp; confidence: {e(f.confidence)}</p>
      <p>{e(f.detail)}</p>
      {f'<ul class="ev">{ev}</ul>' if ev else ''}
      {f'<p class="fix"><strong>Remediation:</strong> {e(f.remediation)}</p>' if f.remediation else ''}
    </article>""")

    pills = "".join(
        f'<span class="pill" style="--c:{sevcol[s.value]}">{s.value} {counts[s.value]}</span>'
        for s in SEV_ORDER)
    fmt_rows = "".join(
        f"<tr><td><code>{e(fr.path)}</code></td><td>{e(fr.format)}</td>"
        f"<td>{fr.size:,}</td><td>{'yes' if fr.inspected else 'no'}</td></tr>"
        for fr in sorted(result.files, key=lambda x: -x.size)[:200])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ML supply-chain scan — {e(result.target.identifier)}</title>
<style>
 :root{{font-family:ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.55}}
 body{{margin:0;background:#f6f7f9;color:#0f172a}}
 .wrap{{max-width:1000px;margin:0 auto;padding:32px 20px 80px}}
 h1{{font-size:1.5rem;margin:0 0 4px}} .sub{{color:#64748b;font-size:.9rem;margin:0 0 24px}}
 .verdict{{background:{vcol};color:#fff;padding:18px 22px;border-radius:12px;
   display:flex;justify-content:space-between;align-items:center;margin-bottom:8px}}
 .verdict b{{font-size:1.6rem;letter-spacing:.04em}}
 .pill{{display:inline-block;border:1px solid var(--c);color:var(--c);border-radius:999px;
   padding:2px 10px;font-size:.75rem;margin:12px 6px 20px 0;font-weight:600}}
 .finding{{background:#fff;border:1px solid #e2e8f0;border-left-width:5px;border-radius:10px;
   padding:14px 18px;margin:0 0 14px}}
 .finding h3{{font-size:1rem;margin:6px 0}}
 .badge{{color:#fff;border-radius:5px;padding:1px 8px;font-size:.7rem;font-weight:700}}
 .rule{{font-family:ui-monospace,monospace;font-size:.72rem;color:#64748b;margin-left:8px}}
 .loc{{font-size:.82rem;color:#475569;margin:2px 0 8px}}
 .ev{{background:#f1f5f9;border-radius:6px;padding:8px 8px 8px 26px;font-size:.78rem}}
 .fix{{font-size:.85rem;color:#334155;background:#f0fdf4;padding:8px 10px;border-radius:6px}}
 code{{font-family:ui-monospace,monospace;font-size:.82em}}
 table{{width:100%;border-collapse:collapse;background:#fff;font-size:.8rem;
   border:1px solid #e2e8f0;border-radius:10px;overflow:hidden}}
 th,td{{text-align:left;padding:7px 10px;border-bottom:1px solid #eef2f7}}
 th{{background:#f8fafc}} h2{{font-size:1.05rem;margin:34px 0 12px}}
</style></head><body><div class="wrap">
<h1>ML Supply-Chain Scan</h1>
<p class="sub">{e(result.target.identifier)} · {e(result.target.kind)} ·
   scanner {e(result.scanner_version)} · {e(str(result.finished_at))}</p>
<div class="verdict"><span>Verdict</span><b>{e(result.verdict)}</b>
  <span>risk score {result.risk_score}/100</span></div>
<div>{pills}</div>
<h2>Findings ({len(result.findings)})</h2>
{''.join(cards) if cards else '<p>No findings.</p>'}
<h2>Inventory</h2>
<table><thead><tr><th>Path</th><th>Format</th><th>Bytes</th><th>Inspected</th></tr></thead>
<tbody>{fmt_rows}</tbody></table>
</div></body></html>"""
