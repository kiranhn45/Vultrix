import pytest

from valtrix import __version__
from valtrix.cli import EXIT_BAD_INPUT, EXIT_OK, main


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_no_command_prints_help(capsys):
    assert main([]) == EXIT_OK
    assert "scan" in capsys.readouterr().out


def test_scan_directory_without_requirements(tmp_path, capsys):
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Target:" in out
    assert "No requirements.txt found" in out


def test_scan_lists_dependencies(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nflask>=3.0\n# comment\n==broken\n"
    )
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Found 2 dependencies" in out
    assert "requests" in out and "2.31.0" in out
    assert "flask" in out and "not pinned" in out
    assert "1 lines could not be used" in out
    assert "requirements.txt:4" in out


def test_scan_unreadable_requirements_file(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_bytes(b"\x80\x81\x82\xfa\xfb")
    assert main(["scan", str(tmp_path)]) == EXIT_BAD_INPUT
    assert "not valid" in capsys.readouterr().err


def test_scan_missing_path(tmp_path, capsys):
    missing = tmp_path / "nope"
    assert main(["scan", str(missing)]) == EXIT_BAD_INPUT
    assert "does not exist" in capsys.readouterr().err


def test_scan_file_instead_of_directory(tmp_path, capsys):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.31.0\n")
    assert main(["scan", str(f)]) == EXIT_BAD_INPUT
    assert "not a directory" in capsys.readouterr().err
