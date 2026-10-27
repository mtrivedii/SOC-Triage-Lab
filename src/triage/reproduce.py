"""`triage reproduce`: check that the committed results/ can be regenerated from the repo.

1. Runs the test suite (pytest; network blocked by tests/conftest.py).
2. Re-runs every offline eval script with output redirected to a temporary folder
   (TRIAGE_RESULTS_DIR), the network blocked (triage.netguard) and API-key variables removed.
3. Compares each generated report with the committed file in results/ (line endings ignored)
   and prints a unified diff for any mismatch.

Exit 0 if everything matches, 1 otherwise. No API calls are possible from here.
"""

from __future__ import annotations

import difflib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from triage.runsets import RESULTS, ROOT

EVAL_DIR = ROOT / "eval"
# Every offline report generator, in dependency-free order. Each writes into TRIAGE_RESULTS_DIR.
EVAL_SCRIPTS = (
    "detector_baseline.py",
    "triage_eval.py",
    "checker_rescore.py",
    "injection_report.py",
    "defence1_offline.py",
    "defences_report.py",
    "detector_v2_offline.py",
    "v2_regression.py",
    "blind_report.py",
    "parser_fix_report.py",
)

_BOOTSTRAP = (
    "import runpy, sys; sys.path.insert(0, {eval_dir!r}); sys.argv = [{script!r}]; "
    "from triage import netguard; netguard.install(); "
    "runpy.run_path({script!r}, run_name='__main__')"
)


def _norm(text: str) -> list[str]:
    return text.replace("\r\n", "\n").splitlines(keepends=True)


def compare(generated_dir: Path, committed_dir: Path) -> list[str]:
    """Unified diffs (one string per mismatching file); empty if all generated files match."""
    diffs = []
    for gen in sorted(p for p in generated_dir.iterdir() if p.is_file()):
        committed = committed_dir / gen.name
        new = _norm(gen.read_text(encoding="utf-8"))
        if not committed.exists():
            diffs.append(f"--- results/{gen.name}: generated but not committed\n")
            continue
        old = _norm(committed.read_text(encoding="utf-8"))
        if old != new:
            diffs.append("".join(difflib.unified_diff(
                old, new, fromfile=f"results/{gen.name} (committed)",
                tofile=f"results/{gen.name} (regenerated)")))
    return diffs


def _env(out_dir: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().endswith("_API_KEY")}
    env["TRIAGE_RESULTS_DIR"] = str(out_dir)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def run(skip_tests: bool = False) -> int:
    if not skip_tests:
        print("== pytest")
        tests = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=ROOT, check=False)
        if tests.returncode != 0:
            print("FAIL: tests failed")
            return 1

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)
        env = _env(out_dir)
        failed = False
        for name in EVAL_SCRIPTS:
            code = _BOOTSTRAP.format(eval_dir=str(EVAL_DIR), script=str(EVAL_DIR / name))
            proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, check=False,
                                  capture_output=True, text=True, encoding="utf-8")
            status = "ok" if proc.returncode == 0 else "FAILED"
            print(f"== eval/{name}: {status}")
            if proc.returncode != 0:
                failed = True
                print(proc.stderr[-3000:])
        generated = sorted(p.name for p in out_dir.iterdir() if p.is_file())
        diffs = compare(out_dir, RESULTS)

    for d in diffs:
        print(d)
    if failed or diffs:
        print(f"FAIL: {len(diffs)} report(s) differ from the committed results/"
              + (", and at least one eval script failed" if failed else ""))
        return 1
    tests = "tests skipped" if skip_tests else "tests passed"
    print(f"OK: {tests}; {len(generated)} regenerated reports match results/: "
          + ", ".join(generated))
    return 0
