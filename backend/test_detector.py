import os
from detector import analyze
from generate_demo import generate

def test_demo_detects_all_types(tmp_path):
    p = tmp_path / "t.log"
    generate(str(p), n=2000)
    r = analyze(str(p), os.path.join(os.path.dirname(__file__), "signatures.json"))
    types = {t["type"] for t in r["by_type"]}
    assert {"sql_injection", "xss", "directory_traversal", "brute_force"} <= types
    assert r["summary"]["malformed"] == 0
