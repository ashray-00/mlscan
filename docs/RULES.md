# Rule catalogue

Generated from `rule_id` literals under `mlscan/`. Do not hand-edit IDs —
`tests/test_rules_doc.py` fails if any codebase rule is missing from this table.

| Rule ID | Severity | Analyzer | Description | Remediation |
|---|---|---|---|---|
| `MLSC-CFG-000` | LOW | `metadata` | Unparseable config.json | See finding detail. |
| `MLSC-CFG-001` | HIGH | `metadata` | config.json declares `auto_map` (requires trust_remote_code) | Read every referenced .py file, or refuse trust_remote_code. |
| `MLSC-CFG-002` | HIGH | `metadata` | Custom pipeline declared in config | Refuse, or vendor and review the pipeline code. |
| `MLSC-CFG-003` | MEDIUM | `metadata` | f"Remote URL embedded in config field `{key}`" | See finding detail. |
| `MLSC-ENG-001` | MEDIUM | `scanner` | Decompressed payload exceeds size limit | See finding detail. |
| `MLSC-ENG-002` | MEDIUM | `scanner` | f"Failed to decompress {fmt} stream" | See finding detail. |
| `MLSC-ENG-003` | MEDIUM | `scanner` | compressed stream not analyzable on this interpreter | Re-run on a newer interpreter, or decompress offline. |
| `MLSC-ENG-004` | MEDIUM | `scanner` | Compressed ZIP stream requires manual extraction | Decompress offline and re-scan the archive. |
| `MLSC-FILE-001` | ? | `scanner` | f"Unexpected file type in model repository ({why})" | Inspect the file; treat the repository as untrusted. |
| `MLSC-FILE-002` | HIGH | `scanner` | f"File content does not match its extension ({ext})" | Reject the file. |
| `MLSC-FMT-001` | LOW | `pickle_scan` | Pickle-based serialization in use | Prefer .safetensors; convert with `safetensors.torch.save_file`. |
| `MLSC-GGUF-001` | INFO | `formats` | GGUF weights (no code execution on load) | Keep llama.cpp / GGUF runtimes patched. |
| `MLSC-GGUF-002` | LOW | `formats` | Unexpected GGUF version field | See finding detail. |
| `MLSC-H5-001` | HIGH | `formats` | Keras Lambda layer in HDF5 model | Reject, or reconstruct the architecture manually and load weights only. |
| `MLSC-H5-002` | MEDIUM | `formats` | f"Suspicious literal in HDF5 attributes: {marker}" | Inspect the attribute manually with h5py. |
| `MLSC-KRS-001` | HIGH | `formats` | Keras Lambda layer present | Load only with keras.models.load_model(..., safe_mode=True), or reject. |
| `MLSC-KRS-002` | HIGH | `formats` | Keras config references builtins module | Reject or load with safe_mode=True and an explicit custom_objects allowlist. |
| `MLSC-KRS-003` | HIGH | `formats` | ? | Reject, or load with safe_mode=True and an explicit custom_objects allowlist ... |
| `MLSC-LFS-001` | LOW | `scanner` | Git LFS pointer scanned instead of real bytes | Fetch LFS objects before scanning. |
| `MLSC-NB-001` | ? | `metadata` | Notebook contains shell escapes or process calls | Read before running; never 'Run All' on an untrusted notebook. |
| `MLSC-NPY-000` | LOW | `formats` | Unreadable or truncated numpy .npy buffer | See finding detail. |
| `MLSC-NPY-001` | HIGH | `formats` | numpy object array (pickle inside .npy) | Never call np.load(..., allow_pickle=True) on untrusted files. |
| `MLSC-ONX-001` | MEDIUM | `formats` | ONNX graph references custom/foreign operators | Run with a restricted op allowlist; audit any custom op library. |
| `MLSC-ONX-002` | MEDIUM | `formats` | Possible external-data path traversal in ONNX model | Validate external data paths before loading. |
| `MLSC-PKL-001` | ? | `pickle_scan` | ? | Do not load this file. Obtain weights in safetensors format from a trusted so... |
| `MLSC-PKL-002` | ? | `pickle_scan` | ? | Manually verify this symbol, or re-export to safetensors. |
| `MLSC-PKL-003` | HIGH | `pickle_scan` | Pickle uses EXT opcodes (copyreg extension registry) | Treat as untrusted; do not load. |
| `MLSC-PKL-004` | MEDIUM | `pickle_scan` | Malformed or truncated pickle stream | Do not load. Re-download from the canonical source and compare hashes. |
| `MLSC-PKL-005` | ? | `pickle_scan` | Suspicious string constants embedded in pickle | Review the literals; commands or URLs in weights are not normal. |
| `MLSC-PRV-001` | LOW | `hub` | Repository created very recently | See finding detail. |
| `MLSC-PRV-002` | LOW | `hub` | Low adoption signal | Weight other findings more heavily for unpopular repos. |
| `MLSC-PRV-003` | INFO | `hub` | Repository is gated | See finding detail. |
| `MLSC-PRV-004` | HIGH | `hub` | Repository is flagged/disabled by the hub | Do not use. |
| `MLSC-PRV-005` | MEDIUM | `hub` | Hub marks this repo as containing custom code | Review all bundled .py files before loading. |
| `MLSC-PRV-006` | MEDIUM | `hub` | f"Publisher account has {n}+ repositories, created within {age_days} days" | Prefer well-known namespaces; verify the publisher identity. |
| `MLSC-PRV-007` | HIGH | `hub` | Local files not listed in hub manifest | Re-download from the hub and re-scan, or treat as untrusted. |
| `MLSC-PY-000` | MEDIUM | `metadata` | Bundled Python file does not parse | Inspect the file manually; do not trust_remote_code. |
| `MLSC-PY-001` | ? | `metadata` | f"Bundled code imports `{alias.name}`" | Do not use trust_remote_code=True with this repo. |
| `MLSC-PY-002` | ? | `metadata` | f"Bundled code calls `{qual}`" | Review manually; refuse trust_remote_code=True. |
| `MLSC-PY-003` | MEDIUM | `metadata` | Module-level side effects in bundled model code | Read these lines before loading the model. |
| `MLSC-PY-004` | MEDIUM | `metadata` | Very long string literal in bundled code | Decode and inspect the literal. |
| `MLSC-REPO-001` | MEDIUM | `metadata` | Weights available only in pickle-based format | Request/convert a safetensors build before adopting. |
| `MLSC-REPO-002` | LOW | `metadata` | Redundant pickle weights alongside safetensors | Delete/ignore the pickle copies; pin use_safetensors=True. |
| `MLSC-REPO-003` | MEDIUM | `metadata` | Python files present but not referenced by config auto_map | Review each file. |
| `MLSC-REPO-004` | LOW | `metadata` | No model card / README | See finding detail. |
| `MLSC-REPO-005` | MEDIUM | `metadata` | f"Build/install artifact in a weights repo: {risky}" | Inspect before use; never `pip install` a model repo blindly. |
| `MLSC-REPO-006` | MEDIUM | `scanner` | Repository ships Python modules | Review each file before loading. |
| `MLSC-SIG-001` | INFO | `provenance` | Signatures/attestations present but unverified | Verify signatures offline against a pinned publisher identity (Sigstore / in-toto / publisher-native). |
| `MLSC-SIG-002` | INFO | `provenance` | Weights ship with no attestation of any kind | Prefer publishers that sign releases once signing is available. |
| `MLSC-SQT-001` | HIGH | `typosquat` | Non-ASCII characters in repository identifier | Copy the identifier from the official source; never retype it. |
| `MLSC-SQT-002` | ? | `typosquat` | f"Organisation name is {bestd} edit(s) from `{best}`" | See finding detail. |
| `MLSC-SQT-003` | HIGH | `typosquat` | Organisation name matches a known org after homoglyph folding | Almost certainly a squat. Do not download. |
| `MLSC-SQT-004` | MEDIUM | `typosquat` | f"Organisation name embeds known org `{orig}`" | See finding detail. |
| `MLSC-SQT-005` | HIGH | `typosquat` | Well-known model name published under an unrecognised org | Fetch from the canonical namespace instead. |
| `MLSC-SQT-006` | ? | `typosquat` | f"Model name is 1 edit from known checkpoint `{best}`" | See finding detail. |
| `MLSC-SQT-007` | LOW | `typosquat` | Unusual separator pattern in organisation name | See finding detail. |
| `MLSC-SQT-008` | ? | `typosquat` | ? | See finding detail. |
| `MLSC-SQT-009` | INFO | `typosquat` | f"typosquat corpus is {corpus.age_days} days old" | Run `mlscan refresh-corpus` and re-scan. |
| `MLSC-STF-000` | MEDIUM | `formats` | Truncated safetensors file | See finding detail. |
| `MLSC-STF-001` | HIGH | `formats` | safetensors header length exceeds file size | Reject; file is malformed or crafted to trigger a parser bug. |
| `MLSC-STF-002` | MEDIUM | `formats` | Abnormally large safetensors header | See finding detail. |
| `MLSC-STF-003` | HIGH | `formats` | Unparseable safetensors header | See finding detail. |
| `MLSC-STF-004` | HIGH | `formats` | Invalid tensor data offsets | See finding detail. |
| `MLSC-STF-005` | HIGH | `formats` | Tensor data offset points past end of file | Reject; out-of-bounds read attempt against the parser. |
| `MLSC-STF-006` | MEDIUM | `formats` | Overlapping tensor regions in safetensors file | See finding detail. |
| `MLSC-STF-007` | LOW | `formats` | Very large free-text values in safetensors __metadata__ | See finding detail. |
| `MLSC-STF-008` | HIGH | `formats` | Tensor shape×dtype does not match data_offsets span | Reject; regenerate or obtain a well-formed safetensors file. |
| `MLSC-TF-001` | ? | `formats` | TensorFlow graph contains filesystem/native-callback ops | Load in a sandbox with no filesystem access, or reject. |
| `MLSC-TPL-001` | CRITICAL | `templates` | Chat template contains Python-introspection tokens | Reject the template. Render only in a sandboxed Jinja environment with no att... |
| `MLSC-TPL-002` | INFO | `templates` | Chat template present | See finding detail. |
| `MLSC-TPL-003` | LOW | `templates` | f"Unparseable config file: {rel}" | Fix or reject the malformed config. |
| `MLSC-ZIP-000` | MEDIUM | `formats` | Corrupt zip container | Re-download and verify checksums. |
| `MLSC-ZIP-001` | CRITICAL | `formats` | Zip entry escapes the extraction directory | Do not extract. Reject the artifact. |
| `MLSC-ZIP-002` | HIGH | `formats` | Symlink entry inside model archive | Do not extract. |
| `MLSC-ZIP-003` | MEDIUM | `formats` | Extreme compression ratio (possible zip bomb) | Cap extraction size; do not decompress untrusted archives in place. |
| `MLSC-ZIP-004` | MEDIUM | `formats` | Oversized pickle member skipped | Inspect manually. |
| `MLSC-ZIP-005` | LOW | `formats` | Unreadable archive member | See finding detail. |
| `MLSC-ZIP-006` | HIGH | `formats` | ? | Inspect the member; treat repo as untrusted. |
| `MLSC-ZIP-007` | MEDIUM | `formats` | TorchScript archive contains serialized Python source | Review the embedded source before torch.jit.load(). |
