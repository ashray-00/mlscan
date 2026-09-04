"""Detection tests. Run: python -m pytest tests/ -v

These assert on rule IDs and verdicts, not on prose, so the wording of a
finding can change without breaking the suite.
"""
from __future__ import annotations

import json
import pickle
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mlscan import hub, pickle_scan, scanner, typosquat  # noqa: E402
from mlscan.findings import Severity  # noqa: E402
from mlscan.scoring import Policy, apply_policy, exit_code  # noqa: E402

FIX = Path(__file__).resolve().parent.parent / "fixtures"


def ensure_fixtures():
    if not FIX.exists():
        subprocess.run([sys.executable, str(Path(__file__).parent / "make_fixtures.py")],
                       check=True)

@pytest.fixture(scope="session", autouse=True)
def _fixtures():
    ensure_fixtures()


def rules(result) -> set[str]:
    return {f.rule_id for f in result.findings}


def scan(name: str):
    r = scanner.scan_local(FIX / name)
    apply_policy(r, Policy())
    return r

# True positives


def test_os_system_payload_blocks():
    r = scan("DO_NOT_LOAD-os-system")
    assert "MLSC-PKL-001" in rules(r)
    assert r.max_severity() is Severity.CRITICAL
    assert r.verdict == "BLOCK"
    assert exit_code(r, Policy()) == 2


def test_legacy_bare_pickle_detected():
    r = scan("DO_NOT_LOAD-legacy-pickle")
    assert "MLSC-PKL-001" in rules(r)
    assert r.verdict == "BLOCK"
    # nested-pickle and network gadgets must each be seen
    titles = " ".join(f.title for f in r.findings)
    assert "pickle.loads" in titles or "pickle" in titles
    assert any("urlopen" in f.title or "urllib" in f.title for f in r.findings)


def test_masquerading_pickle_as_safetensors():
    r = scan("DO_NOT_LOAD-masquerade")
    assert "MLSC-FILE-002" in rules(r)     # extension/content mismatch
    assert "MLSC-FILE-001" in rules(r)     # ELF + shell script
    assert "MLSC-PKL-001" in rules(r)      # payload still found
    assert r.verdict == "BLOCK"


def test_zip_path_traversal():
    r = scan("DO_NOT_LOAD-zip-traversal")
    assert "MLSC-ZIP-001" in rules(r)
    assert r.verdict == "BLOCK"


def test_remote_code_repo():
    r = scan("DO_NOT_LOAD-remote-code")
    got = rules(r)
    assert "MLSC-CFG-001" in got          # auto_map
    assert "MLSC-PY-002" in got           # os.system / eval
    assert "MLSC-PY-003" in got           # module-level side effects
    assert r.verdict == "BLOCK"


def test_safetensors_offset_out_of_bounds():
    r = scan("DO_NOT_LOAD-bad-safetensors")
    assert "MLSC-STF-005" in rules(r)


def test_numpy_object_array():
    r = scan("DO_NOT_LOAD-npy-object")
    assert "MLSC-NPY-001" in rules(r)


def test_notebook_pipe_to_shell_is_high():
    r = scan("DO_NOT_LOAD-notebook")
    nb = [f for f in r.findings if f.rule_id == "MLSC-NB-001"]
    assert nb and nb[0].severity is Severity.HIGH


def test_keras_custom_module():
    r = scan("DO_NOT_LOAD-keras-custom")
    assert "MLSC-KRS-003" in rules(r)


def test_npz_object_array():
    r = scan("DO_NOT_LOAD-npz-abuse")
    assert "MLSC-NPY-001" in rules(r)


def test_compressed_pickle_joblib():
    r = scan("DO_NOT_LOAD-compressed-pickle")
    assert "MLSC-PKL-001" in rules(r)
    assert r.verdict == "BLOCK"


def test_safetensors_shape_span_mismatch():
    r = scan("DO_NOT_LOAD-stf-span")
    assert "MLSC-STF-008" in rules(r)

# False-positive control


def test_clean_safetensors_repo_is_silent():
    r = scan("clean-model")
    # Contract: zero findings above INFO (INFO provenance notes are fine).
    assert not [f for f in r.findings if f.severity.rank > Severity.INFO.rank]
    assert r.verdict == "ALLOW"
    assert r.risk_score == 0
    assert exit_code(r, Policy()) == 0


def test_benign_pickle_is_not_critical():
    """A real state_dict must NOT be flagged as an attack."""
    r = scan("benign-pickle-model")
    assert r.max_severity().rank < Severity.HIGH.rank
    assert r.verdict == "ALLOW"
    assert "MLSC-PKL-001" not in rules(r)


def test_allowlisted_globals_do_not_fire():
    from collections import OrderedDict
    blob = pickle.dumps(OrderedDict([("a", [1, 2]), ("b", {"c": 3})]), protocol=4)
    fs = pickle_scan.scan_pickle_blob(blob, "t.pkl")
    assert not [f for f in fs if f.rule_id in {"MLSC-PKL-001", "MLSC-PKL-002"}]

# Opcode-level behaviour


def test_stack_global_is_resolved():
    """Protocol >=4 emits STACK_GLOBAL; naive scanners that only read GLOBAL miss it."""
    class P:
        def __reduce__(self):
            import os
            return (os.system, ("echo hi",))
    blob = pickle.dumps(P(), protocol=4)
    a = pickle_scan.analyze_pickle_bytes(blob)
    mods = {m for m, _, _ in a.globals_found}
    assert mods & {"os", "posix", "nt"}, f"unresolved: {a.globals_found}"
    assert any(n == "REDUCE" for n, _ in a.call_opcodes)


def test_protocol_2_global_opcode():
    class P:
        def __reduce__(self):
            import os
            return (os.system, ("echo hi",))
    blob = pickle.dumps(P(), protocol=2)
    fs = pickle_scan.scan_pickle_blob(blob, "t.pkl")
    assert any(f.severity is Severity.CRITICAL for f in fs)


def test_truncated_pickle_flagged():
    blob = pickle.dumps({"a": 1}, protocol=4)[:-3]
    fs = pickle_scan.scan_pickle_blob(blob, "t.pkl")
    assert "MLSC-PKL-004" in {f.rule_id for f in fs}


def test_staged_payload_without_call_is_downgraded_not_dropped():
    """GLOBAL with no REDUCE is still reported, one notch lower."""
    import pickletools, io
    blob = b"\x80\x04cposix\nsystem\n."
    fs = pickle_scan.scan_pickle_blob(blob, "t.pkl")
    hits = [f for f in fs if f.rule_id == "MLSC-PKL-001"]
    assert hits and hits[0].severity is Severity.HIGH

# Typosquatting
@pytest.mark.parametrize("rid,expect", [
    ("meta-llama/Llama-2-7b", set()),
    ("google/gemma-7b-it", set()),
    ("sentence-transformers/all-MiniLM-L6-v2", set()),
    ("meta_llama/Llama-2-7b", {"MLSC-SQT-008"}),
    ("rnicrosoft/phi-2", {"MLSC-SQT-003"}),
    ("goog1e/gemma-7b-it", {"MLSC-SQT-003"}),
    ("nvvidia/parakeet", {"MLSC-SQT-002"}),
    ("randomuser/bert-base-uncased", {"MLSC-SQT-005"}),
    ("meta-llama-official/llama-3-8b", {"MLSC-SQT-004"}),
    ("\u0430pple/clip-vit-base-patch32", {"MLSC-SQT-001"}),
])


def test_typosquat(rid, expect):
    got = {f.rule_id for f in typosquat.check_identifier(rid)}
    assert expect <= got, f"{rid}: expected {expect}, got {got}"


def test_no_squat_findings_on_known_good():
    for rid in ("google/gemma-7b-it", "openai-community/gpt2", "tiiuae/falcon-7b-instruct"):
        assert typosquat.check_identifier(rid) == [], rid


def test_damerau_transposition():
    assert typosquat.damerau_levenshtein("openai", "opneai") == 1
    assert typosquat.damerau_levenshtein("abc", "abc") == 0


def test_deconfuse_does_not_self_cancel():
    """Regression: chained bidirectional substitutions used to undo each other."""
    assert "microsoft" in typosquat.deconfuse("rnicrosoft")

# Remote zip parser -- exercised offline against a local file


def test_remote_zip_central_directory_parser(tmp_path):
    """Prove the Range-based reader parses real zips without touching the network."""
    zp = tmp_path / "shard.bin"
    payload = pickle.dumps({"weights": [1, 2, 3]}, protocol=4)
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("archive/data.pkl", payload)
        z.writestr("archive/data/0", b"\x00" * 4096)

    blob = zp.read_bytes()

    class LocalZip(hub.RemoteZip):
        def _range(self, start, end):
            return blob[start:end + 1]

    rz = LocalZip(url="file://local")
    rz.size = len(blob)
    rz._final_url = "file://local"
    rz._read_central_directory()

    names = [e.name for e in rz.entries]
    assert "archive/data.pkl" in names
    assert rz.read("archive/data.pkl") == payload


def test_scoring_monotonic():
    from mlscan.findings import Category, Finding
    from mlscan.scoring import compute_score
    low = [Finding("X", "t", Severity.LOW, Category.METADATA, "f")]
    crit = [Finding("X", "t", Severity.CRITICAL, Category.EXECUTION, "f")]
    assert compute_score(crit) > compute_score(low)
    assert compute_score([]) == 0
    assert compute_score(crit * 10) <= 100


def test_policy_allow_pickle_suppresses_format_noise():
    r = scanner.scan_local(FIX / "benign-pickle-model")
    apply_policy(r, Policy(allow_pickle=True))
    assert "MLSC-FMT-001" not in rules(r)


def test_baseline_suppresses_known_findings(tmp_path):
    from mlscan.baseline import apply_baseline, write_baseline
    r1 = scanner.scan_local(FIX / "DO_NOT_LOAD-os-system", hash_files=True)
    apply_policy(r1, Policy())
    bl = tmp_path / "baseline.json"
    write_baseline(r1, bl)
    r2 = scanner.scan_local(FIX / "DO_NOT_LOAD-os-system", hash_files=True)
    apply_baseline(r2, bl)
    apply_policy(r2, Policy())
    assert r2.findings == []


def test_cyclonedx_shape():
    from mlscan import report
    r = scan("DO_NOT_LOAD-os-system")
    doc = json.loads(report.render_cyclonedx(r))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert any(c.get("type") == "machine-learning-model" for c in doc["components"])
    assert any(c.get("type") == "file" for c in doc["components"])
    assert doc["vulnerabilities"]
    assert all(v["source"]["name"] == "mlscan" for v in doc["vulnerabilities"])
    assert all(not str(v["id"]).startswith("CVE-") for v in doc["vulnerabilities"])


def test_jobs_deterministic_json():
    a = scanner.scan_local(FIX / "DO_NOT_LOAD-masquerade", hash_files=True, jobs=1)
    b = scanner.scan_local(FIX / "DO_NOT_LOAD-masquerade", hash_files=True, jobs=8)
    apply_policy(a, Policy())
    apply_policy(b, Policy())
    da, db = a.to_dict(), b.to_dict()
    for d in (da, db):
        d.pop("started_at", None)
        d.pop("finished_at", None)
    assert json.dumps(da, sort_keys=True) == json.dumps(db, sort_keys=True)


def test_provenance_unsigned_is_info():
    r = scan("clean-model")
    assert "MLSC-SIG-002" in rules(r)
    assert all(f.severity is Severity.INFO
               for f in r.findings if f.rule_id == "MLSC-SIG-002")

# fileid protocol-0 guard
PROTO0_LOOKALIKES = [
    "class Foo: pass\n",
    "class Model(nn.Module):\n    pass\n",
    "colour = 'red'\n",
    "(lambda x: x)(1)\n",
    "]  # stray bracket\n",
    "}\n",
    "S3 bucket notes\n",
    "Various notes here\n",
    "In this README we explain\n",
    "Longer description follows\n",
    "Km per hour\n",
    "None of these are pickles\n",
]

@pytest.mark.parametrize("src", PROTO0_LOOKALIKES)
def test_python_source_is_not_a_pickle(tmp_path, src):
    from mlscan.utils import identify
    p = tmp_path / "sample.py"
    p.write_text(src)
    got = identify(str(p))
    assert got != "pickle", (
        f"{src!r} misidentified as pickle; protocol-0 trial-parse guard broken")

@pytest.mark.parametrize("proto", [0, 1, 2, 3, 4, 5])
def test_real_pickles_still_detected(tmp_path, proto):
    from mlscan.utils import identify
    p = tmp_path / f"p{proto}.pkl"
    p.write_bytes(pickle.dumps({"weights": [1.0, 2.0], "name": "x"}, protocol=proto))
    assert identify(str(p)) == "pickle", f"protocol {proto} pickle missed"


def test_protocol0_pickle_specifically(tmp_path):
    from mlscan.utils import identify
    data = pickle.dumps({"a": 1}, protocol=0)
    assert data[:1] == b"("
    p = tmp_path / "legacy.pkl"
    p.write_bytes(data)
    assert identify(str(p)) == "pickle"


def test_truncated_pickle_is_not_silently_pickle(tmp_path):
    from mlscan.utils import identify
    full = pickle.dumps({"a": 1}, protocol=0)
    p = tmp_path / "cut.pkl"
    p.write_bytes(full[: len(full) // 2])
    assert identify(str(p)) != "pickle"


def test_template_config_jinja_escape():
    r = scan("DO_NOT_LOAD-template-config")
    assert "MLSC-TPL-001" in rules(r)
    assert r.max_severity() is Severity.CRITICAL


def test_lfs_pointer_finding():
    r = scan("DO_NOT_LOAD-lfs-pointer")
    assert "MLSC-LFS-001" in rules(r)


def test_explain_trailing_second_pickle(capsys):
    from mlscan.explain import explain
    explain(FIX / "DO_NOT_LOAD-appended-pickle" / "appended.pkl")
    out = capsys.readouterr().out
    assert "looks like a second pickle: True" in out
    assert "trailing bytes after STOP" in out


def test_online_flag_is_required_for_network(monkeypatch):
    import mlscan.hub as hub_mod

    def boom(*a, **k):
        raise AssertionError("network call without --online")

    monkeypatch.setattr(hub_mod, "_get", boom)
    r = scanner.scan_local(
        FIX / "clean-model",
        repo_id="meta-llama/Llama-3.1-8B-Instruct",
        online=False,
    )
    apply_policy(r, Policy())
    assert r.verdict == "ALLOW"
