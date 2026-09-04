# Limitations

`mlscan` is a static supply-chain audit for ML model artifacts. It produces triage
signals for human review, not guarantees. A clean result means "nothing this tool
knows how to detect," which is not the same as "safe."

Keep this file in sync with the `LIMITATIONS` constant in `mlscan/cli.py`.

---

## Detects

Grouped by rule-ID prefix (`MLSC-*`):

### Pickle / unsafe serialization (`MLSC-PKL`, `MLSC-FMT`)

- Dangerous GLOBAL / STACK_GLOBAL imports recovered via stack+memo simulation
- Unknown reconstruction globals outside the allowlist
- Unresolvable `EXT` (copyreg) opcodes
- Truncated / malformed pickle streams
- Suspicious string constants embedded in pickle payloads
- Presence of pickle-based weight formats (`MLSC-FMT-001`)

### Archives / containers (`MLSC-ZIP`)

- Zip Slip / path traversal and absolute paths
- Symlink members
- Extreme compression ratios (zip-bomb heuristic)
- Executable / script members inside weight archives
- TorchScript embedded `code/` Python
- Oversized or unreadable members (fail-loud)

### Keras / HDF5 (`MLSC-KRS`, `MLSC-H5`)

- Lambda layers (marshalled bytecode)
- Custom objects resolving into `builtins`
- Custom `module` / `registered_name` outside the Keras/TF namespace
- Suspicious literals in HDF5 attribute blobs

### Safe tensor formats (`MLSC-STF`, `MLSC-NPY`, `MLSC-GGUF`, `MLSC-ONX`, `MLSC-TF`)

- Malformed safetensors headers, out-of-bounds / overlapping offsets, shape×dtype span mismatches
- Object-dtype `.npy` / `.npz` (pickle inside NumPy)
- ONNX custom-op domains and external-data path traversal hints
- TensorFlow SavedModel graph ops with filesystem / Python callbacks
- GGUF version anomalies (informational baseline)

### Remote code / bundled source (`MLSC-CFG`, `MLSC-PY`, `MLSC-NB`, `MLSC-REPO`)

- `auto_map` / custom pipelines in `config.json`
- AST analysis of bundled `.py` (dangerous imports/calls, module-level side effects)
- Notebook shell escapes and curl|sh patterns
- Shadow pickle weights, unreferenced Python, install/build artifacts in weight repos

### Naming / provenance (`MLSC-SQT`, `MLSC-PRV`)

- Homoglyphs, edit-distance near-misses, separator confusion, combosquatting, namespace confusion
- Hub reputation signals (age, downloads, gating, disabled, `custom_code` tag)

### File anomalies (`MLSC-FILE`)

- Unexpected native binaries / scripts in a weights tree
- Extension vs magic-byte disagreement (masquerade)

---

## Does NOT detect

- **Backdoored weights.** A model trained to misbehave on a trigger phrase is a
  byte-for-byte normal safetensors file. That is a behavioural-evaluation problem,
  not a file-format one. Nothing here helps.
- **Data poisoning.** Same reasoning, one step upstream of training.
- **Encrypted or runtime-decrypted payloads.** Bytes that only become meaningful
  after an in-process decrypt step are opaque to static inspection.
- **Novel gadgets absent from the denylist.** Unknown callables surface as
  `MLSC-PKL-002` (MEDIUM), not CRITICAL. Coverage is finite by design.
- **Pickle `EXT` opcode targets.** Flagged as unresolvable (`MLSC-PKL-003`); never
  pretended-resolved against a runtime copyreg registry.
- **Signature validity.** Signatures / attestations may be inventoried when present
  (`MLSC-SIG-001` / `MLSC-SIG-002`), but cryptographic verification is unimplemented —
  publishers largely do not sign models yet.
- **Runtime behaviour of custom ops / native libraries.** Detection is inventory and
  name-based, not execution in a sandbox.

---

## Known false-positive sources

- Legitimate models that ship `auto_map` / custom code (`MLSC-CFG-001`, `MLSC-PY-*`) —
  flagged as a decision the user must make, not as confirmed malice.
- Benign pickle state_dicts that import reconstruction helpers outside the small
  allowlist (`MLSC-PKL-002` MEDIUM).
- Separator or capitalisation differences in hub namespaces that are intentional
  republishers (`MLSC-SQT-008`).
- Low hub download/like counts on brand-new legitimate repos (`MLSC-PRV-002`).
- ONNX models with vendor custom-op domains that are expected for that runtime
  (`MLSC-ONX-001`).
- Redundant `.bin` siblings next to safetensors in dual-format releases
  (`MLSC-REPO-002`).

---

## Known false-negative sources

- **Git LFS pointers** scan as tiny text stubs because the real weight bytes were
  never fetched. Enable `lfs: true` in CI; when a pointer is recognised the tool
  should say so rather than report clean.
- **Files over the configured size limit** are skipped with an error note — an
  unscanned file is not a clean file, but content inside it is unseen.
- **Typosquat corpus staleness.** The reference org/model sets are vendored; names
  that post-date the corpus will not match. Refresh periodically.
- Compressed streams or formats the interpreter cannot decompress (e.g. zstd on
  older Python) degrade to a finding that analysis was incomplete.
- Gadgets reached only through runtime state the static pickle VM cannot reconstruct.
- Weights hosted behind auth / gated downloads when running without a token — hub
  deep inspection degrades to "no reputation / no remote pickle data."
