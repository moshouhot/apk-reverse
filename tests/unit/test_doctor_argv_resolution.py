"""Doctor's argv resolution, exercised without the tools it looks for.

The defect this pins is recorded in `doctor.py`'s `_windows_argv` docstring: on
Windows `subprocess.run(['apktool', ...])` raises FileNotFoundError because
`shell=False` reaches CreateProcess, which appends `.exe` and nothing else --
`.bat`/`.cmd` are never considered. `apktool`, `jadx` and `apksigner` all ship as
`.BAT` shims on a typical reverse-engineering host, so the doctor reported
`exit 127: not found` for three tools that work, and `readelf` (a pip-installed
`.PY`, rejected by CreateProcess with WinError 193) as a fourth.

The assertions are about **argv construction**, not about this host's tool set:
nothing here needs apktool, adb, a device or the network. Each case states the
property that must hold on every platform, and the Windows-only rewrites are
skipped with a reason elsewhere rather than asserted into a green tick.
"""
from __future__ import annotations

import os
import sys

import pytest

from conftest import load_script

doctor = load_script("doctor.py")

pytestmark = pytest.mark.unit

ON_WINDOWS = os.name == "nt"
windows_only = pytest.mark.skipif(
    not ON_WINDOWS, reason="argv[0] rewriting for .BAT/.CMD/.PY shims is a Windows-only path")


# --------------------------------------------------------------------------- #
# Invariants that hold on every platform
# --------------------------------------------------------------------------- #
def test_arguments_are_never_touched():
    """Only argv[0] may be rewritten.

    Device commands are handed to subprocess as argv lists precisely so the host
    shell never expands `$`, `|`, `>` or `;` before adb sees them (the property
    tests/integration/test_adb_command_construction.py exists to protect). A
    resolution step that rewrote arguments would quietly undo that.
    """
    argv = ["adb", "-s", "emulator-5554", "shell", "echo $HOME | cat > /tmp/x; id"]
    out = doctor._windows_argv(argv)
    assert out[1:] == argv[1:]


def test_unknown_program_is_left_alone():
    """A tool that is not installed must still fail as missing, not be invented."""
    argv = ["apkrev-no-such-tool-7c1f", "--version"]
    assert doctor._windows_argv(argv) == argv


def test_empty_argv_is_not_indexed():
    """`cmd[0]` on an empty list would be an IndexError inside a probe."""
    assert doctor._windows_argv([]) == []


def test_run_reports_a_missing_program_as_127():
    """The failure channel the report reads: 127, never an exception."""
    rc, _ = doctor.run(["apkrev-no-such-tool-7c1f", "--version"], timeout=20)
    assert rc == 127


def test_absolute_path_to_a_missing_file_is_reported_not_raised():
    """An explicit bad path must not escape as OSError either."""
    missing = os.path.join(os.sep, "apkrev", "definitely", "absent", "tool")
    rc, _ = doctor.run([missing, "--version"], timeout=20)
    assert rc in (126, 127)


def test_run_bounds_a_hanging_probe():
    """A tool that never exits must not hang the doctor."""
    rc, detail = doctor.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1)
    assert rc == 124
    assert "TIMEOUT" in detail


def test_run_decodes_non_utf8_output():
    """A GBK console must not turn into a crash: decode is 'replace', not strict."""
    rc, txt = doctor.run(
        [sys.executable, "-c",
         "import sys; sys.stdout.buffer.write(b'ok\\xff\\xfe done')"], timeout=30)
    assert rc == 0
    assert "done" in txt


# --------------------------------------------------------------------------- #
# Windows shim handling
# --------------------------------------------------------------------------- #
@windows_only
def test_bat_shim_is_resolved_to_its_full_path(tmp_path):
    """The measured defect: a bare `.bat` name is not startable, a full path is."""
    shim = tmp_path / "fake_tool.BAT"
    shim.write_text("@echo off\r\necho SHIM_RAN\r\n", encoding="ascii")
    rc, txt = doctor.run([str(shim)], timeout=30)
    assert rc == 0
    assert "SHIM_RAN" in txt


@windows_only
def test_py_shim_runs_through_its_shebang_interpreter(tmp_path):
    """CreateProcess rejects a `.PY` (WinError 193); the shebang names a real host.

    Built with an explicit shebang rather than relying on file association, which
    is what the pip-installed `readelf.PY` carries and what made that probe fail.
    """
    script = tmp_path / "fake_tool.PY"
    script.write_text(
        "#!%s\nprint('PY_SHIM_RAN')\n" % sys.executable, encoding="utf-8")
    rc, txt = doctor.run([str(script)], timeout=30)
    assert rc == 0
    assert "PY_SHIM_RAN" in txt


@windows_only
def test_bat_that_calls_another_bat_returns(tmp_path):
    """Guards against a `cmd /c` wrapper, which never returns for a nested bat.

    jadx's shim is exactly this shape (`call "…\\jadx.bat" %*`). Wrapping it in
    `cmd /c` makes the outer call wait forever instead of returning.
    """
    inner = tmp_path / "inner.BAT"
    inner.write_text("@echo off\r\necho INNER_RAN\r\n", encoding="ascii")
    outer = tmp_path / "outer.BAT"
    outer.write_text('@echo off\r\ncall "%s" %%*\r\n' % inner, encoding="ascii")
    rc, txt = doctor.run([str(outer)], timeout=30)
    assert rc == 0
    assert "INNER_RAN" in txt


@windows_only
def test_resolution_preserves_a_device_subcommand_after_rewrite():
    """adb is found by name; its arguments still reach it untouched."""
    resolved = doctor._windows_argv(["adb", "-s", "SERIAL", "shell", "ps -A"])
    assert resolved[1:] == ["-s", "SERIAL", "shell", "ps -A"]
    if doctor.which("adb"):
        assert resolved[0] != "adb"          # rewritten to a startable path
        assert os.path.isfile(resolved[0])   # and that path exists
    else:
        assert resolved[0] == "adb"          # absent tool: left as a bare name
