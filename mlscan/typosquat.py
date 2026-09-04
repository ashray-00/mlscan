"""Typosquatting / namespace-confusion detection for model hub identifiers."""
from __future__ import annotations

import re
import unicodedata

from .data.popular import STALE_DAYS, load_refreshed_corpus
from .findings import Category, Finding, Severity

# Back-compat aliases for tests / callers that import the seed sets directly.
from .data.popular import SEED_MODELS as KNOWN_MODELS  # noqa: F401
from .data.popular import SEED_ORGS as KNOWN_ORGS  # noqa: F401

# Visually confusable substitutions used by squatters.
CONFUSABLES = [
    ("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"),
    ("1", "l"), ("l", "1"), ("l", "i"), ("i", "l"), ("1", "i"),
    ("0", "o"), ("o", "0"), ("5", "s"), ("s", "5"), ("cl", "d"),
]

_SEP = re.compile(r"[-_.\s]+")


def canonical(s: str) -> str:
    """Aggressive normalisation: unicode-fold, lowercase, drop separators."""
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = s.lower()
    s = _SEP.sub("", s)
    return s


def deconfuse(s: str) -> set[str]:
    """Return every string reachable by applying confusable substitutions.

    Naive chaining is WRONG: applying ("rn"->"m") then ("m"->"rn") to
    "rnicrosoft" gives back "rnicrosoft", so the squat is never detected.
    We generate candidates instead, to a bounded depth.
    """
    seen = {s}
    frontier = {s}
    for _ in range(2):                    # depth 2 covers realistic squats
        nxt = set()
        for cur in frontier:
            for a, b in CONFUSABLES:
                if a in cur:
                    cand = cur.replace(a, b)
                    if cand not in seen and len(seen) < 512:
                        seen.add(cand)
                        nxt.add(cand)
        frontier = nxt
        if not frontier:
            break
    return seen


def damerau_levenshtein(a: str, b: str, cap: int = 4) -> int:
    """Optimal string alignment distance, early-exit at `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + cost)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[len(b)]


def has_non_ascii(s: str) -> bool:
    return any(ord(c) > 127 for c in s)


def check_identifier(repo_id: str) -> list[Finding]:
    """repo_id is 'org/model' or bare 'model' (canonical/legacy namespace)."""
    out: list[Finding] = []
    loc = repo_id
    corpus = load_refreshed_corpus()
    known_orgs = corpus.orgs
    known_models = corpus.models

    if corpus.age_days is not None and corpus.age_days > STALE_DAYS:
        out.append(Finding(
            "MLSC-SQT-009",
            f"typosquat corpus is {corpus.age_days} days old",
            Severity.INFO, Category.NAMING, loc,
            detail=("The reference org/model sets used for name-confusion checks "
                    f"were last refreshed {corpus.age_days} days ago (threshold "
                    f"{STALE_DAYS}). Stale corpora miss newly famous names and "
                    "produce false negatives."),
            evidence=[f"refreshed_at={corpus.refreshed_at}",
                      f"corpus_size={corpus.size}"],
            confidence="high",
            remediation="Run `mlscan refresh-corpus` and re-scan."))

    if has_non_ascii(repo_id):
        weird = [f"{c!r} U+{ord(c):04X} ({unicodedata.name(c, '?')})"
                 for c in repo_id if ord(c) > 127]
        out.append(Finding(
            "MLSC-SQT-001", "Non-ASCII characters in repository identifier",
            Severity.HIGH, Category.NAMING, loc,
            detail=("Homoglyph attacks substitute Cyrillic/Greek lookalikes for Latin "
                    "letters so the name renders identically to the real one."),
            evidence=weird[:6],
            remediation="Copy the identifier from the official source; never retype it."))

    if "/" in repo_id:
        org, _, model = repo_id.partition("/")
    else:
        org, model = "", repo_id

    corg, cmodel = canonical(org), canonical(model)
    known_orgs_c = {canonical(o): o for o in known_orgs}
    known_models_c = {canonical(m): m for m in known_models}

    org_is_known = corg in known_orgs_c
    org_is_exact = org in known_orgs

    # `meta_llama` normalises to the same string as `meta-llama` but is a
    # DIFFERENT account. Underscore/dot/hyphen swaps are the cheapest squat
    # available and the easiest for a human to misread.
    if org and org_is_known and not org_is_exact:
        known = known_orgs_c[corg]
        case_only = org.lower() == known.lower()
        out.append(Finding(
            "MLSC-SQT-008",
            ("Organisation differs from a known org only by capitalisation"
             if case_only else
             "Organisation differs from a known org only by separator characters"),
            Severity.LOW if case_only else Severity.HIGH, Category.NAMING, loc,
            detail=("Hub namespaces are distinct accounts: `meta_llama` and `meta-llama` "
                    "are different publishers. Separator swaps render almost identically, "
                    "while capitalisation differences are usually just sloppy copy-paste."),
            evidence=[f"observed `{org}` vs known `{known}`"],
            confidence="low" if case_only else "high",
            remediation=f"Use the exact namespace `{known}`."))

    if org and not org_is_known:
        matches = sorted({known_orgs_c[c] for c in deconfuse(corg)
                          if c in known_orgs_c and c != corg})
        if matches:
            out.append(Finding(
                "MLSC-SQT-003", "Organisation name matches a known org after homoglyph folding",
                Severity.HIGH, Category.NAMING, loc,
                detail=("Character substitution (rn->m, 1->l, 0->o, vv->w) produces a "
                        "visually near-identical name."),
                evidence=[f"`{org}` folds to `{m}`" for m in matches[:3]],
                remediation="Almost certainly a squat. Do not download."))
        else:
            best, bestd = None, 99
            for k, orig in known_orgs_c.items():
                d = damerau_levenshtein(corg, k, cap=3)
                if d < bestd:
                    best, bestd = orig, d
            if best and 0 < bestd <= 2:
                out.append(Finding(
                    "MLSC-SQT-002", f"Organisation name is {bestd} edit(s) from `{best}`",
                    Severity.HIGH if bestd == 1 else Severity.MEDIUM, Category.NAMING, loc,
                    detail=("The publishing namespace closely resembles a well-known "
                            "organisation but is not it."),
                    evidence=[f"observed `{org}` vs known `{best}` (distance {bestd})"],
                    remediation=f"Verify you meant `{best}/…`."))
            else:
                for k, orig in known_orgs_c.items():
                    if len(k) >= 5 and k in corg and k != corg:
                        out.append(Finding(
                            "MLSC-SQT-004", f"Organisation name embeds known org `{orig}`",
                            Severity.MEDIUM, Category.NAMING, loc,
                            detail=("Squatters append words like -ai, -official, -team, -hf "
                                    "to borrow the reputation of a real namespace."),
                            evidence=[f"`{org}` contains `{orig}`"], confidence="medium",
                            remediation=f"Check whether the model exists under `{orig}/` itself."))
                        break

    if org and not org_is_known and cmodel in known_models_c:
        out.append(Finding(
            "MLSC-SQT-005", "Well-known model name published under an unrecognised org",
            Severity.HIGH, Category.NAMING, loc,
            detail=("The model basename matches a famous checkpoint but the namespace "
                    "is not its known publisher. This is the classic re-upload lure: "
                    "same name, attacker-controlled weights."),
            evidence=[f"model `{model}` is normally published by a known org, found under `{org}`"],
            remediation="Fetch from the canonical namespace instead."))

    if cmodel not in known_models_c:
        best, bestd = None, 99
        for k, orig in known_models_c.items():
            d = damerau_levenshtein(cmodel, k, cap=2)
            if d < bestd:
                best, bestd = orig, d
        if best and 0 < bestd <= 1:
            out.append(Finding(
                "MLSC-SQT-006", f"Model name is 1 edit from known checkpoint `{best}`",
                Severity.MEDIUM if org_is_known else Severity.HIGH,
                Category.NAMING, loc,
                detail="Near-identical model names catch copy-paste and typo traffic.",
                evidence=[f"observed `{model}` vs `{best}`"], confidence="medium",
                remediation=f"Confirm you intended `{best}`."))

    if org and (org.startswith("-") or org.endswith("-") or "--" in org):
        out.append(Finding(
            "MLSC-SQT-007", "Unusual separator pattern in organisation name",
            Severity.LOW, Category.NAMING, loc,
            evidence=[org], confidence="low",
            detail="Leading/trailing/doubled hyphens are common in throwaway squat accounts."))
    return out


def last_corpus_info():
    """Expose corpus metadata for scanners to attach to ScanResult."""
    return load_refreshed_corpus()
