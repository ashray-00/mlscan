# mlscan

**Static supply-chain audit for machine-learning model artifacts.**

A scanner that inspects model repositories — Hugging Face IDs, local checkpoint directories, or single weight files — for unsafe serialization formats, embedded code, bundled foreign artifacts, metadata inconsistency, and repository-name confusion. Think of it as software composition analysis for the ML supply chain.

Zero required dependencies. Python 3.10+. Never executes the artifact it inspects.

```bash
$ mlscan scan ./downloaded-model --no-color
==============================================================================
 ML SUPPLY-CHAIN SCAN  ·  ./downloaded-model
 target type: local
==============================================================================

 VERDICT:  BLOCK    risk score: 66/100
 CRITICAL=1  HIGH=0  MEDIUM=1  LOW=2  INFO=1

 ── CRITICAL (1) ────────────────────────────────────────
  [MLSC-PKL-001] Dangerous global imported by pickle: posix.system
      location : pytorch_model.bin!archive/data.pkl
      The pickle stream imports `posix.system` (shell command
      execution). Call opcodes present: ['REDUCE']. Loading this file
      with torch.load / pickle.load would execute this reference.
      fix      : Do not load this file. Obtain weights in safetensors
                 format from a trusted source.
```

---

## Why this exists

Application security has spent twenty years learning to audit the software supply chain: lockfiles, SBOMs, SCA tooling, package signing, dependency-confusion detection. When a developer runs `npm install`, a lot of machinery quietly checks they aren't about to install something terrible.

Now consider:

```python
model = AutoModelForCausalLM.from_pretrained("some-org/some-model")
```

That line downloads several gigabytes of opaque binary data uploaded by an unverified account and deserializes it inside the current Python process. Depending on format and library version, deserializing it executes arbitrary code as the current user — with their network access, environment variables, and cloud credentials.

No lockfile. No signature. Usually no SBOM. Conventional tooling has nothing to say about it: SAST parses source code and a `.safetensors` file isn't source code; SCA resolves declared dependencies and a model repo declares none; AV matches known-bad signatures and a malicious pickle is unique per attacker.

The knowledge needed to close that gap is specific: you have to understand the **serialization formats**, because that's where the execution primitive lives.

---

## Threat model

**Assets:** the developer workstation or CI runner that loads the model; the inference server that serves it.

**Adversary can:** register any hub account and publish any unclaimed repository name; upload arbitrary files of arbitrary format with arbitrary names; write a convincing model card and fabricate benchmarks; fork a real repo and change one file; get their repo linked from a blog post, a Stack Overflow answer, or a hallucinated LLM response.

**Adversary generally cannot:** take over the authentic namespace of a major publisher; modify a file after you've pinned and verified its hash.

**Trust boundary:** crossed the moment hub bytes touch your filesystem. Everything after — deserialization, config parsing, template rendering, custom module import — runs as you.

**Consequence:** the scanner must never deserialize or execute what it inspects. Every analyzer here is static. Formats are parsed by hand. There is no `pickle.load`, no `torch.load`, no `np.load`, no `keras.models.load_model` anywhere in this codebase. A scanner that executes its input is a delivery mechanism, not a defence.

---

## What it detects

### Unsafe deserialization

Python's `pickle` is not a data format — it's bytecode for a stack machine, and two of its opcodes (`GLOBAL` to import a name, `REDUCE` to call it) give arbitrary code execution to whoever controls the bytes. Every one of these is pickle underneath: `pytorch_model.bin`, `*.pt`, `*.pth`, `*.ckpt`, `*.pkl`, `*.joblib`, `*.npz`, and `*.npy` with `dtype=object`.

`mlscan` disassembles pickle streams with `pickletools.genops` and **simulates the stack and the memo** to recover imports that a naive scanner misses:

- `GLOBAL` (`c`) carries its target as a literal argument — easy.
- `STACK_GLOBAL` (`\x93`, protocol 4) *pops two strings off the stack*. Raw disassembly shows `arg=None`.
- An attacker can push those strings, memoize them, bury them under unrelated opcodes, then re-fetch with `BINGET` immediately before `STACK_GLOBAL`. Scanners that check "the previous two opcodes" see nothing.

Modelling the memo defeats that. It's the technical core of the tool.

Also detected: data appended after the `STOP` opcode (invisible to disassembly, still reachable by loaders), `copyreg` `EXT` opcodes whose targets can't be statically resolved, and `REDUCE` with no resolvable callable.

### Non-pickle code execution

| Path | Detection |
|---|---|
| Keras `Lambda` layers (marshalled bytecode in the model config) | `MLSC-KRS-001` |
| Keras custom `module` outside keras/tensorflow | `MLSC-KRS-003` |
| Jinja2 sandbox-escape tokens in `chat_template` (incl. `tokenizer_config.json`) | `MLSC-TPL-001` |
| Object-dtype `.npy` / `.npz` (pickle inside NumPy) | `MLSC-NPY-001` |
| Gzip/bzip2/xz-wrapped pickles (joblib-style) | decompress → `MLSC-PKL-*` |
| Safetensors shape×dtype ≠ `data_offsets` span | `MLSC-STF-008` |
| ONNX custom-op domains dispatching to host Python | `MLSC-ONX-001` |
| Zip Slip — archive entries escaping the extraction directory | `MLSC-ZIP-001` |
| Native `.so`/`.dll`/`.dylib` or shell scripts bundled with weights | `MLSC-FILE-001`, `MLSC-ZIP-006` |
| Git LFS pointer stubs (real bytes never fetched) | `MLSC-LFS-001` |


### Remote code by design

The most-used path in real incidents involves no serialization trickery at all. A `config.json` with an `auto_map` block points `transformers` at Python modules in the same repository; `trust_remote_code=True` imports them, and import executes module-level code. The weights can be pristine safetensors and it doesn't matter, because the `.py` next to them ran first.

This isn't flagged as malicious — plenty of legitimate models need it. It's flagged as **a decision the user must consciously make**, with the contents of the referenced modules surfaced so they can make it. Bundled `.py` is analysed with the `ast` module (parsing is not execution) rather than regex — `getattr(__import__("os"), "system")` and `chr()`-built names are in scope. A file that fails to parse emits `MLSC-PY-000` (MEDIUM) instead of being silently skipped.

### Repository-name confusion

Six distinct classes, because a single edit-distance threshold catches only two of them:

| Class | Example | Rule |
|---|---|---|
| Character substitution | `openai` → `opemai` | `TSQ002` |
| Transposition | `llama` → `lalma` | `TSQ002` |
| Homoglyph | `llama` → `llаma` (Cyrillic а) | `TSQ001` |
| Separator variation | `meta-llama` → `meta_llama` | `TSQ002` |
| Combosquatting | `meta-llama-official` | `TSQ002` |
| **Namespace confusion** | `randomuser/Llama-3.1-8B-Instruct` | `TSQ003` |

The last one is the important one and it's **invisible to edit distance on the full ID** — the strings are wildly different, yet the risk is high, because the model name is copied verbatim so every log line and doc string downstream looks correct. Anyone can publish any model name under their own namespace. *The namespace is the only identity signal that means anything.*

The engine normalizes names to a **skeleton** (NFKC, homoglyph mapping, combining-mark removal, digit confusables `0`→`o`/`1`→`l`, digraph confusables `rn`→`m`, separator removal, casefold) so that `meta-llama`, `Meta_LLaMA`, `metallama`, and `meta-llarna` all collapse to `metallama`. Skeleton equality is a much stronger signal than a distance-2 near-miss, and is scored accordingly.

### Cross-file consistency

Single-file analysis asks "is this file dangerous?" Consistency analysis asks whether the repository **tells a coherent story about itself**:

- **Shadow weights** (`CON001`) — the same weights as both `.safetensors` and `.bin`. A reviewer inspects the safe one; an older loader reads the other.
- **Manifest drift** (`CON005`) — a weight file on disk that isn't in `model.safetensors.index.json`. Exactly what gets added when an attacker wants a loader that globs to pick up their file.
- **Config/weights disagreement** (`CON007`–`CON009`) — `config.json` declares `vocab_size: 128256`; the actual embedding tensor is 32000×512. The config was copied from a more reputable model to look familiar.

---

## Design principles

1. **Never execute the input.** Parse formats by hand.
2. **Never trust the extension.** All routing keys off magic-byte identification. Disagreement between extension and content is itself a finding (`MLSC-FILE-002`) — a `.safetensors` that's really a pickle defeats every filename-based allowlist in existence.
3. **Denylist *and* allowlist.** A denylist alone is bypassed by any gadget you haven't listed (`numpy.testing._private.utils.runstring` is a real function in a trusted library that evaluates a string — nobody would think to block it until they'd seen it used). An allowlist alone is too noisy to ship. Both, at different severities: known-dangerous is CRITICAL, outside the known reconstruction vocabulary is MEDIUM.
4. **Fail loud, not silent.** A parse error is a finding, not a skip. An unscanned file is not a clean file.
5. **Zero required dependencies.** Adding a package that itself resolves and downloads remote content into a supply-chain scanner is poor form — and the tool must run air-gapped, which is exactly where you want to inspect an untrusted artifact.

---

## Install

```bash
git clone <your-repo-url> && cd mlscan
pip install -e .
mlscan --version
```

Development extras (just `pytest`):

```bash
pip install -e '.[dev]'
```

---

## Usage

```bash
# Scan a local directory or single file
mlscan scan ./model-dir
mlscan scan ./pytorch_model.bin

# Also run name checks against a hub ID (still offline)
mlscan scan ./model-dir --repo-id some-org/some-model

# Add hub reputation metadata (opt-in; degrades gracefully offline)
mlscan scan ./model-dir --repo-id some-org/some-model --online

# Triage a repository name without downloading anything
mlscan name meta-llarna/Llama-3.1-8B-Instruct
mlscan hub meta-llarna/Llama-3.1-8B-Instruct          # same offline name check
mlscan hub meta-llarna/Llama-3.1-8B-Instruct --online # + reputation

# Manually disassemble a pickle stream (annotated stack+memo simulation)
mlscan explain suspicious.pkl
mlscan explain model.pt --member archive/data.pkl

# Refresh the typosquat reference corpus from the Hub (unions into seed sets)
mlscan refresh-corpus --limit 1000
```

Reports that run name checks record corpus size and age under `remote_metadata`
(`typosquat_corpus_*`). If a refreshed file is older than 90 days, `MLSC-SQT-009`
is emitted at INFO so triage can see the data may be stale.

### Output formats

```bash
mlscan scan ./model --format text     # human at a terminal (default)
mlscan scan ./model --format json     # includes the full hashed inventory
mlscan scan ./model --format sarif    # SARIF 2.1.0 → GitHub code scanning
mlscan scan ./model --format html -o report.html
mlscan scan ./model --format cyclonedx -o bom.json   # CycloneDX 1.6 ML-BOM
```

The JSON inventory doubles as a minimal ML-BOM: every file with size, SHA-256, and content-detected type. `--format cyclonedx` emits a full CycloneDX 1.6 document with findings mapped into `vulnerabilities` (rule ID as `id`, `source.name = mlscan` — no invented CVEs).

### Baseline / diff mode

```bash
# Capture known findings once hashes are stable
mlscan scan ./model --hash --write-baseline baseline.json

# Later: only new (rule_id, path, sha256) triples fail the gate
mlscan scan ./model --hash --baseline baseline.json --policy policy.json
```

New findings are marked `[NEW]` in text output and `"is_new": true` in JSON. This is what makes the gate adoptable on a repo that already has known findings.

### Parallelism and analyzer filters

```bash
mlscan scan ./model --jobs 8
mlscan scan ./model --only pickle_scan --only formats
mlscan scan ./model --skip typosquat --skip hfhub
```

Default `--jobs` is `min(8, cpu_count)`. Findings are sorted after collection so JSON output is byte-identical across job counts.

### Docker (network-isolated scan of an untrusted artifact)

```bash
docker build -t mlscan .
docker run --rm --network=none -v "$PWD/untrusted-model:/work:ro" mlscan scan /work
```

The image is `python:3.12-slim`, runs as a non-root user, and uses `ENTRYPOINT ["mlscan"]`.

### Exit codes

| Code | Verdict | Meaning |
|---|---|---|
| `0` | `ALLOW` | nothing at or above the review threshold |
| `1` | `REVIEW` | human should look before loading |
| `2` | `BLOCK` | do not load |
| `3` | — | tool error |

### Policy

```json
{
  "fail_on": "HIGH",
  "block_score": 60,
  "review_score": 20,
  "allow_pickle": false,
  "allow_remote_code": false,
  "allowlist_repos": [],
  "ignore_rules": ["MLSC-REPO-004"]
}
```

`ignore_rules` suppresses noisy hygiene findings in CI. `allow_pickle` / `allow_remote_code` are blunt escape hatches when you already accept those load paths. See [`examples/policy.json`](examples/policy.json).

```bash
mlscan scan ./model --policy examples/policy.json
```

---

## Scoring vs. verdict

Two decisions, deliberately kept separate.

**Score** (0–100) is for humans: sorting a queue, trending over time. Severity weights × confidence, with decay so the tenth MEDIUM contributes less than the first.

**Verdict** is the gate, driven by the **maximum severity present**, not by the score. A single CRITICAL must never be outvoted by an absence of other findings. The verdict is **monotone**: adding a finding can never make it less severe.

The detection matrix below shows why this matters — `DO_NOT_LOAD-template-config` scores 55 with a single CRITICAL finding and still blocks. If the score alone drove the gate without the severity floor, a lone Jinja sandbox escape would be easier to argue down.

---

## Detection matrix

Fixtures generated by `tests/make_fixtures.py`. All payloads are inert (`echo`, `eval("1+1")`) — detection keys on *which callable is imported*, not on what it's asked to do.

| Fixture                       | Score | Verdict | Exit | Rules fired |
|-------------------------------|-------|---------|------|-------------|
| `clean-model` | 0 | ALLOW | 0 | — |
| `benign-pickle-model` | 10 | ALLOW | 0 | MLSC-FMT-001, MLSC-REPO-001 |
| `DO_NOT_LOAD-appended-pickle` | 11 | ALLOW | 0 | MLSC-FMT-001, MLSC-REPO-001, MLSC-REPO-004 |
| `DO_NOT_LOAD-keras-custom` | 23 | REVIEW | 1 | MLSC-KRS-003, MLSC-REPO-004 |
| `DO_NOT_LOAD-notebook` | 23 | REVIEW | 1 | MLSC-NB-001, MLSC-REPO-004 |
| `DO_NOT_LOAD-npy-object` | 23 | REVIEW | 1 | MLSC-NPY-001, MLSC-REPO-004 |
| `DO_NOT_LOAD-npz-abuse` | 23 | REVIEW | 1 | MLSC-NPY-001, MLSC-REPO-004 |
| `DO_NOT_LOAD-stf-span` | 23 | REVIEW | 1 | MLSC-REPO-004, MLSC-STF-008 |
| `DO_NOT_LOAD-lfs-pointer` | 24 | REVIEW | 1 | MLSC-FILE-002, MLSC-LFS-001 |
| `DO_NOT_LOAD-bad-safetensors` | 37 | REVIEW | 1 | MLSC-REPO-004, MLSC-STF-005, MLSC-STF-008 |
| `DO_NOT_LOAD-template-config` | 55 | BLOCK | 2 | MLSC-TPL-001 |
| `DO_NOT_LOAD-compressed-pickle` | 58 | BLOCK | 2 | MLSC-FMT-001, MLSC-PKL-001, MLSC-REPO-004 |
| `DO_NOT_LOAD-os-system` | 66 | BLOCK | 2 | MLSC-FMT-001, MLSC-PKL-001, MLSC-REPO-001, MLSC-REPO-004 |
| `DO_NOT_LOAD-zip-traversal` | 88 | BLOCK | 2 | MLSC-FMT-001, MLSC-REPO-001, MLSC-REPO-004, MLSC-ZIP-001, MLSC-ZIP-006 |
| `DO_NOT_LOAD-legacy-pickle` | 100 | BLOCK | 2 | MLSC-FMT-001, MLSC-PKL-001, MLSC-PKL-005, MLSC-REPO-001, MLSC-REPO-004 |
| `DO_NOT_LOAD-masquerade` | 100 | BLOCK | 2 | MLSC-FILE-001, MLSC-FILE-002, MLSC-FMT-001, MLSC-PKL-001, MLSC-REPO-004, MLSC-REPO-005 |
| `DO_NOT_LOAD-remote-code` | 100 | BLOCK | 2 | MLSC-CFG-001, MLSC-PY-001, MLSC-PY-002, MLSC-PY-003, MLSC-REPO-004 |

Zero findings above INFO on the clean control. That test — `test_clean_safetensors_repo_is_silent` — is the most important one in the suite.

```bash
python -m tests.make_fixtures
python -m pytest tests/ -q
# 64 passed
```

---

## CI integration

```yaml
- uses: actions/checkout@v4
  with:
    lfs: true          # without this you scan 130-byte LFS pointer stubs

- run: mlscan scan models/ --policy examples/policy.json --format sarif -o mlscan.sarif
  continue-on-error: true

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mlscan.sarif

- run: mlscan scan models/ --policy examples/policy.json      # enforce the gate
```

Three load-bearing details: `lfs: true` (otherwise you scan pointer stubs and get a meaningless clean result); a scheduled weekly re-scan (the globals denylist and typosquat corpus both go stale — run `mlscan refresh-corpus`); two invocations so SARIF reaches the dashboard even when the gate fails; and `--baseline` / `--write-baseline` so an existing repo with known findings can adopt the gate without going dark on day one.

Full workflow in [`.github/workflows/model-scan.yml`](.github/workflows/model-scan.yml).

---

## Architecture

```
   ACQUIRE  →  walk, SHA-256, identify by magic bytes  →  List[FileRecord]
      ↓
  IDENTIFY  →  content-based type detection, routes to analyzers
      ↓
   ANALYZE  →  per-file:  pickle_scan, formats, metadata, provenance
               repo-wide: hygiene, consistency, templates
               name/hub:  typosquat (+ optional online reputation)
      ↓                                                 →  List[Finding]
     SCORE  →  policy suppression → risk score → verdict
      ↓
    REPORT  →  text │ json │ sarif │ html │ cyclonedx   →  exit code
```

```
mlscan/
├── cli.py              argparse, exit codes, LIMITATIONS text
├── findings.py         Severity, Finding, FileRecord, ScanResult
├── utils.py            magic-byte identification + hashing (`identify`)
├── scoring.py          Policy, risk score, verdict
├── scanner.py          orchestration — routes files to analyzers
├── hub.py              optional Hub metadata (stdlib urllib only)
├── pickle_scan.py      pickle VM simulation  ← the centrepiece
├── explain.py          `mlscan explain` annotated disassembly
├── formats.py          ZIP / safetensors / GGUF / NPY / HDF5 / ONNX
├── metadata.py         auto_map, Python AST, notebooks, consistency
├── templates.py        chat_template Jinja escape scan (TPL*)
├── provenance.py       signature / attestation inventory
├── typosquat.py        name-confusion engine
├── baseline.py         --baseline / --write-baseline
├── report.py           text, json, sarif, html, cyclonedx
└── data/
    └── popular.py      reference corpus (+ refreshed JSON union)
```

---

## Limitations

Read [`LIMITATIONS.md`](LIMITATIONS.md) in full (`mlscan limitations` prints the short form). The short version:

**Does not detect backdoored weights.** A model trained to misbehave on a trigger phrase is a byte-for-byte normal safetensors file. Nothing here helps. That's a behavioural-evaluation problem — the malice is in the parameter values, not the container.

**Does not detect data poisoning.** Same reasoning, one step upstream.

**Signatures are inventoried but not verified.** Presence of `.sig` / Sigstore /
in-toto artifacts yields `MLSC-SIG-001` (INFO); absence yields `MLSC-SIG-002`
(INFO). Cryptographic verification is unimplemented — publishers largely do not
sign models yet. When they do, that check becomes the highest-value one in the tool.

**Cannot statically resolve everything.** Pickle `EXT` opcodes resolve through a runtime registry. They're flagged as unresolvable (`MLSC-PKL-003`) rather than pretended-resolved.

**Reputation signals are correlational, never dispositive.** Every legitimate repository is zero days old with zero downloads on its first day.

**Allowlist coverage is finite.** A novel gadget in a library not in the knowledge base surfaces as MEDIUM `MLSC-PKL-002`, not CRITICAL.

**A Git LFS pointer scans clean** because the real bytes were never fetched — enable `lfs: true` in CI.

---

## Notes from building it

A couple of details that only surfaced by running the thing:

**On Linux, findings say `posix.system`, not `os.system`.** `os.system` is re-exported from the `posix` builtin module, and that's the name that lands in the pickle. A denylist containing only `os.system` misses it entirely on Linux. Both are in the knowledge base.

**`class Foo: pass` starts with `c` — the protocol-0 `GLOBAL` opcode.** Early builds identified Python source files as pickles. The fix isn't a filename exclusion; it's requiring the bytes to actually parse to `STOP` via a trial `genops` walk. Structural proof, not a guess. There's a labelled regression test (`test_python_source_is_not_a_pickle`).

**Gzip-wrapped pickles were identified and then dropped.** `fileid` returned `gzip` for joblib-style payloads, but the engine had no decompress branch — a silent skip that looked like a clean file. Decompression is now bounded (64 MB + bomb ratio) and re-dispatches on the inner magic.

**`.npz` object arrays hid behind ZIP of `.npy`.** Members start with `\x93NUMPY`, not `\x80`, so pickle-looking checks inside archives missed them until the npy parser ran on member bytes.

**`tokenizer_config.json` was the real chat-template location.** Early coverage only looked at safetensors `__metadata__` / GGUF KV blocks. A live `__class__.__mro__.__subclasses__()` escape in `tokenizer_config.json` scanned clean until `templates.py` walked JSON configs for Jinja. Coverage claims that don't have an end-to-end fixture are lies.

---

## Rule catalogue

| Prefix | Domain |
|---|---|
| `MLSC-PKL` / `MLSC-FMT` | pickle opcode analysis / unsafe format presence |
| `MLSC-ZIP` | archive/container abuse |
| `MLSC-KRS` / `MLSC-H5` | Keras Lambda / HDF5 |
| `MLSC-STF` | safetensors structural validation |
| `MLSC-NPY` / `MLSC-GGUF` / `MLSC-ONX` / `MLSC-TF` | NumPy, GGUF, ONNX, TensorFlow graphs |
| `MLSC-CFG` / `MLSC-PY` / `MLSC-NB` / `MLSC-REPO` | remote code, Python AST, notebooks, repo hygiene |
| `MLSC-TPL` | chat templates / Jinja escapes |
| `MLSC-FILE` | unexpected types / extension masquerade |
| `MLSC-SQT` | typosquatting |
| `MLSC-PRV` | hub reputation |
| `MLSC-SIG` | signature / attestation inventory |
| `MLSC-ENG` / `MLSC-LFS` | engine / decompression limits, Git LFS pointers |

Full ID-by-ID table in [`docs/RULES.md`](docs/RULES.md).

---

## License

MIT — see [`LICENSE`](LICENSE).

## Disclaimer

A defensive audit tool. It produces triage signals for human review, not guarantees. A clean result means "nothing this tool knows how to detect," which is not the same as "safe." Do not use it as the only control between an untrusted artifact and a production system.