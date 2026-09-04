"""Model-registry admission gate — reject artifacts at promotion time.

Drop this into (or call from) your registry webhook / promotion controller.
Example usage is documentation; wire `admit` into your service's handler.
"""
from __future__ import annotations

import json
from pathlib import Path

from mlscan import scanner
from mlscan.scoring import Policy, apply_policy


def admit(model_dir: str, policy_path: str) -> tuple[bool, dict]:
    result = scanner.scan_local(Path(model_dir))
    apply_policy(result, Policy.from_dict(json.loads(Path(policy_path).read_text())))
    return result.verdict != "BLOCK", result.to_dict()


# Pair with a pre-download gate in your fetch wrapper:
#
#   mlscan hub "$REPO_ID" --fail-on HIGH || { echo "refusing to download $REPO_ID"; exit 1; }
#   huggingface-cli download "$REPO_ID"
