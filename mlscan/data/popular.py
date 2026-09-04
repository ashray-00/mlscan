"""Reference corpus for typosquat detection.

The seed sets are vendored so the tool works fully offline and stays
reproducible in tests. `mlscan refresh-corpus` writes
`corpus_refreshed.json` beside this module; `load_refreshed_corpus`
unions that file with the seeds when present.

A stale corpus produces false negatives on newly famous names — every
scan report therefore records corpus size and age so the triage UI can
admit how fresh the reference data is.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SEED_ORGS = {
    "meta-llama", "google", "openai", "openai-community", "mistralai",
    "microsoft", "facebook", "huggingface", "hf-internal-testing", "bigscience",
    "stabilityai", "runwayml", "nvidia", "eleutherai", "tiiuae", "databricks",
    "cohereforai", "qwen", "deepseek-ai", "allenai", "sentence-transformers",
    "bigcode", "salesforce", "intel", "apple", "ibm-granite", "01-ai",
    "togethercomputer", "mosaicml", "anthropic", "amazon", "baai", "thudm",
    "laion", "timm", "openmmlab", "ultralytics", "kakaobrain", "naver-clova-ix",
    "xlm-roberta", "distilbert", "state-spaces", "nousresearch", "teknium",
    "unsloth", "bartowski", "thebloke", "lmsys", "vikhyatk", "black-forest-labs",
}

SEED_MODELS = {
    "llama-2-7b", "llama-2-13b", "llama-2-70b", "llama-3-8b", "llama-3-70b",
    "meta-llama-3-8b-instruct", "llama-3.1-8b-instruct", "llama-3.2-1b",
    "bert-base-uncased", "bert-large-uncased", "roberta-base", "gpt2",
    "gpt2-medium", "gpt2-large", "gpt2-xl", "t5-base", "t5-small", "flan-t5-base",
    "distilbert-base-uncased", "xlm-roberta-base", "clip-vit-base-patch32",
    "stable-diffusion-v1-5", "stable-diffusion-xl-base-1.0", "sdxl-turbo",
    "whisper-large-v3", "whisper-base", "wav2vec2-base-960h",
    "mistral-7b-instruct-v0.2", "mixtral-8x7b-instruct-v0.1",
    "phi-2", "phi-3-mini-4k-instruct", "gemma-7b-it", "gemma-2-9b-it",
    "qwen2-7b-instruct", "deepseek-coder-6.7b-instruct",
    "all-minilm-l6-v2", "all-mpnet-base-v2", "codellama-7b",
    "falcon-7b-instruct", "mpt-7b-instruct", "vicuna-7b-v1.5",
}

CORPUS_PATH = Path(__file__).with_name("corpus_refreshed.json")
STALE_DAYS = 90

@dataclass
class CorpusInfo:
    orgs: set[str]
    models: set[str]
    size: int
    refreshed_at: str | None  # ISO timestamp or None when seed-only
    age_days: int | None
    source: str  # "seed" | "seed+refreshed"
    error: str | None = None


def _age_days(iso: str) -> int | None:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return None


def load_refreshed_corpus(path: Path | None = None) -> CorpusInfo:
    """Union seed sets with `corpus_refreshed.json` when present.

    Missing file → silent seed fallback. Corrupt file → seed fallback plus
    an error note the caller can attach to `ScanResult.errors`.
    """
    path = path or CORPUS_PATH
    orgs = set(SEED_ORGS)
    models = set(SEED_MODELS)
    refreshed_at = None
    source = "seed"
    err = None

    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            orgs |= {str(x) for x in (data.get("orgs") or []) if x}
            models |= {str(x) for x in (data.get("models") or []) if x}
            refreshed_at = data.get("refreshed_at")
            source = "seed+refreshed"
        except Exception as exc:
            err = f"typosquat corpus unreadable ({path.name}): {type(exc).__name__}: {exc}"

    age = _age_days(refreshed_at) if refreshed_at else None
    return CorpusInfo(
        orgs=orgs,
        models=models,
        size=len(orgs) + len(models),
        refreshed_at=refreshed_at,
        age_days=age,
        source=source,
        error=err,
    )


def write_refreshed_corpus(orgs: set[str], models: set[str],
                           path: Path | None = None) -> Path:
    path = path or CORPUS_PATH
    payload = {
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
        "orgs": sorted(orgs),
        "models": sorted(models),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def corpus_metadata(info: CorpusInfo) -> dict:
    return {
        "typosquat_corpus_size": info.size,
        "typosquat_corpus_source": info.source,
        "typosquat_corpus_refreshed_at": info.refreshed_at,
        "typosquat_corpus_age_days": info.age_days,
    }
