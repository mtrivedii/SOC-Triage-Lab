"""Reproducibility helpers: run-set cutoff, output redirection, committed-vs-regenerated diff."""

from triage import reproduce, runsets


def test_frozen_excludes_runs_after_the_cutoff_and_keeps_undated_ones():
    records = [
        {"id": "old", "ts": "2026-10-22T10:00:00+00:00"},
        {"id": "undated"},  # original Sprint 5 injection runs carry no ts
        {"id": "late", "ts": "2026-11-01T09:00:00+00:00"},
    ]
    assert [r["id"] for r in runsets.frozen(records)] == ["old", "undated"]


def test_out_path_follows_triage_results_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGE_RESULTS_DIR", str(tmp_path / "out"))
    assert runsets.out_path("x.md") == tmp_path / "out" / "x.md"
    monkeypatch.delenv("TRIAGE_RESULTS_DIR")
    assert runsets.out_path("x.md") == runsets.RESULTS / "x.md"


def test_compare_ignores_line_endings_and_reports_real_differences(tmp_path):
    gen, committed = tmp_path / "gen", tmp_path / "committed"
    gen.mkdir()
    committed.mkdir()
    (gen / "same.md").write_bytes(b"a\nb\n")
    (committed / "same.md").write_bytes(b"a\r\nb\r\n")
    assert reproduce.compare(gen, committed) == []

    (gen / "changed.md").write_bytes(b"total 2/15\n")
    (committed / "changed.md").write_bytes(b"total 9/15\n")
    (gen / "new.md").write_bytes(b"x\n")
    diffs = reproduce.compare(gen, committed)
    assert len(diffs) == 2
    assert "-total 9/15" in diffs[0] and "+total 2/15" in diffs[0]
    assert "generated but not committed" in diffs[1]


def test_every_eval_script_is_listed():
    scripts = {p.name for p in reproduce.EVAL_DIR.glob("*.py")} - {"runsets.py"}
    assert scripts == set(reproduce.EVAL_SCRIPTS)
