"""Exercise the real hermetic wrapper and runner with a disposable pytest file."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell wrapper")
@pytest.mark.parametrize("base", ["f97608f178d1ffeca59860195ab7da295f7c8e5f", ""])
def test_upgrade_base_survives_wrapper_without_credentials(tmp_path, base):
    root = Path(__file__).resolve().parents[2]
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    for name in ("run_tests.sh", "run_tests_parallel.py"):
        shutil.copy2(root / "scripts" / name, scripts / name)
    home = tmp_path / "home"
    home.mkdir()
    probe = tmp_path / "test_probe.py"
    probe.write_text(
        "import os\n"
        "def test_environment():\n"
        f"    assert os.environ.get('HERMES_E2E_UPGRADE_BASE', '') == {base!r}\n"
        "    assert os.environ['HERMES_TEST_WORKERS'] == '2'\n"
        "    assert 'OPENAI_API_KEY' not in os.environ\n"
        "    assert 'HERMES_TEST_SECRET' not in os.environ\n"
    )
    env = {
        "PATH": os.environ["PATH"], "HOME": str(home),
        "HERMES_PYTHON": sys.executable,
        "HERMES_E2E_UPGRADE_BASE": base,
        "HERMES_TEST_WORKERS": "2",
        "OPENAI_API_KEY": "synthetic-must-not-reach-child",
        "HERMES_TEST_SECRET": "synthetic-must-not-reach-child",
    }
    result = subprocess.run(
        ["bash", str(scripts / "run_tests.sh"), str(probe)],
        cwd=tmp_path, env=env, text=True, capture_output=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 tests passed, 0 failed" in result.stdout
    assert "synthetic-must-not-reach-child" not in result.stdout + result.stderr
