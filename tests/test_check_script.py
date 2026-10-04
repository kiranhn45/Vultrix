"""The phase gate must never hang, even when a command leaves a background process behind."""

import importlib.util
import subprocess
import sys
import time
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check.py"


def load_gate():
    spec = importlib.util.spec_from_file_location("valtrix_gate", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Exits at once, but leaves a process running that holds the output handles open.
LEAVES_BACKGROUND_PROCESS = (
    "import subprocess, sys;"
    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)']);"
    "print('finished')"
)


def test_background_process_does_not_block_the_gate():
    gate = load_gate()
    started = time.time()
    result = gate.run([sys.executable, "-c", LEAVES_BACKGROUND_PROCESS], timeout=30)
    assert time.time() - started < 3, "the gate waited for the background process"
    assert result.returncode == 0 and "finished" in result.stdout


def test_stuck_command_times_out_instead_of_hanging():
    gate = load_gate()
    started = time.time()
    result = gate.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
    assert time.time() - started < 10
    assert result.returncode == 124 and "timed out" in result.stderr


def test_command_cannot_wait_for_keyboard_input():
    gate = load_gate()
    result = gate.run([sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"], timeout=10)
    assert result.returncode == 0 and result.stdout.strip() == "''"


def test_output_and_errors_are_captured_separately():
    gate = load_gate()
    result = gate.run([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"])
    assert result.returncode == 3 and result.stdout.strip() == "out" and result.stderr.strip() == "err"


def test_git_commands_switch_off_background_helpers():
    gate = load_gate()
    joined = " ".join(gate.GIT)
    assert "core.fsmonitor=false" in joined and "gc.auto=0" in joined and "maintenance.auto=false" in joined
