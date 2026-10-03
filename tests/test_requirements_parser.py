import pytest

from valtrix.models import Dependency, normalize_name
from valtrix.parsers import RequirementsError, parse_requirements, parse_requirements_text
from valtrix.parsers import requirements as req_module


def one(text):
    result = parse_requirements_text(text)
    assert len(result.dependencies) == 1, result
    return result.dependencies[0]


# ---------------------------------------------------------- single lines

def test_pinned_version():
    dep = one("requests==2.31.0")
    assert dep == Dependency("requests", "2.31.0", "==2.31.0", (), None, "<text>", 1)
    assert dep.is_pinned


def test_name_is_normalized():
    assert one("Flask_SQLAlchemy==3.0.0").name == "flask-sqlalchemy"
    assert normalize_name("zope.interface") == "zope-interface"


def test_unpinned_name():
    dep = one("requests")
    assert dep.version is None
    assert dep.specifier == ""
    assert not dep.is_pinned


def test_version_range_is_not_pinned():
    dep = one("django>=3.2, <4.0")
    assert dep.version is None
    assert dep.specifier == ">=3.2,<4.0"


def test_spaces_around_operator():
    assert one("requests == 2.31.0").version == "2.31.0"


def test_wildcard_is_not_pinned():
    assert one("django==3.2.*").version is None


def test_extras():
    dep = one("requests[socks, Security]==2.31.0")
    assert dep.extras == ("security", "socks")
    assert dep.version == "2.31.0"


def test_environment_marker():
    dep = one('pywin32==306; sys_platform == "win32"')
    assert dep.version == "306"
    assert dep.marker == 'sys_platform == "win32"'


def test_hash_option_is_ignored():
    assert one("requests==2.31.0 --hash=sha256:abcdef").version == "2.31.0"


# ------------------------------------------------------- file structure

def test_comments_and_blank_lines_keep_line_numbers():
    text = "# top comment\n\nflask==3.0.0  # inline comment\n   \n# another\nnumpy==1.26.0\n"
    result = parse_requirements_text(text)
    assert [(d.name, d.line) for d in result.dependencies] == [("flask", 3), ("numpy", 6)]
    assert result.issues == []


def test_line_continuation():
    dep = one("flask \\\n  ==3.0.0\n")
    assert dep.version == "3.0.0"
    assert dep.line == 1


def test_empty_text():
    result = parse_requirements_text("")
    assert result.dependencies == [] and result.issues == []


# --------------------------------------------------- things we can't use

def test_unparseable_line_becomes_issue():
    result = parse_requirements_text("requests==2.31.0\n==1.0\nflask!!3\n")
    assert [d.name for d in result.dependencies] == ["requests"]
    assert [i.line for i in result.issues] == [2, 3]
    assert "Could not parse" in result.issues[0].message


def test_unsupported_option_becomes_issue():
    result = parse_requirements_text("--index-url https://example.com/simple\nflask==3.0.0\n")
    assert len(result.dependencies) == 1
    assert "Unsupported option" in result.issues[0].message


def test_direct_url_keeps_package_but_reports_issue():
    result = parse_requirements_text("mypkg @ https://example.com/mypkg.zip\n")
    dep = result.dependencies[0]
    assert dep.name == "mypkg" and dep.version is None
    assert dep.specifier.startswith("@")
    assert "direct URL" in result.issues[0].message


def test_include_in_text_mode_is_reported_not_followed():
    result = parse_requirements_text("-r base.txt\n")
    assert result.dependencies == []
    assert "not followed" in result.issues[0].message


# ----------------------------------------------------------------- files

def test_parse_file_with_include(tmp_path):
    (tmp_path / "base.txt").write_text("requests==2.31.0\n")
    (tmp_path / "requirements.txt").write_text("-r base.txt\nflask==3.0.0\n")
    result = parse_requirements(tmp_path / "requirements.txt")
    found = {(d.name, d.source) for d in result.dependencies}
    assert found == {("requests", "base.txt"), ("flask", "requirements.txt")}
    assert result.issues == []


@pytest.mark.parametrize("form", ["-r base.txt", "-rbase.txt", "--requirement base.txt", "--requirement=base.txt"])
def test_include_spellings(tmp_path, form):
    (tmp_path / "base.txt").write_text("requests==2.31.0\n")
    (tmp_path / "requirements.txt").write_text(form + "\n")
    result = parse_requirements(tmp_path / "requirements.txt")
    assert [d.name for d in result.dependencies] == ["requests"]


def test_missing_include_is_an_issue_not_a_crash(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r missing.txt\nflask==3.0.0\n")
    result = parse_requirements(tmp_path / "requirements.txt")
    assert [d.name for d in result.dependencies] == ["flask"]
    assert "Could not read include" in result.issues[0].message


def test_circular_include_terminates(tmp_path):
    (tmp_path / "a.txt").write_text("-r b.txt\nflask==3.0.0\n")
    (tmp_path / "b.txt").write_text("-r a.txt\nrequests==2.31.0\n")
    result = parse_requirements(tmp_path / "a.txt")
    assert {d.name for d in result.dependencies} == {"flask", "requests"}
    assert any("Circular" in i.message for i in result.issues)


def test_include_outside_project_is_skipped(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (tmp_path / "secret.txt").write_text("evil==1.0\n")
    (project / "requirements.txt").write_text("-r ../secret.txt\nflask==3.0.0\n")
    result = parse_requirements(project / "requirements.txt")
    assert [d.name for d in result.dependencies] == ["flask"]
    assert "outside the project folder" in result.issues[0].message


def test_explicit_root_allows_parent_include(tmp_path):
    (tmp_path / "base.txt").write_text("requests==2.31.0\n")
    sub = tmp_path / "reqs"
    sub.mkdir()
    (sub / "dev.txt").write_text("-r ../base.txt\n")
    result = parse_requirements(sub / "dev.txt", root=tmp_path)
    assert [d.name for d in result.dependencies] == ["requests"]
    assert result.issues == []


def test_url_include_is_skipped(tmp_path):
    (tmp_path / "requirements.txt").write_text("-r https://example.com/reqs.txt\n")
    result = parse_requirements(tmp_path / "requirements.txt")
    assert "URL includes" in result.issues[0].message


def test_include_depth_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(req_module, "MAX_INCLUDE_DEPTH", 2)
    for i in range(4):
        (tmp_path / f"f{i}.txt").write_text(f"-r f{i + 1}.txt\n")
    (tmp_path / "f4.txt").write_text("flask==3.0.0\n")
    result = parse_requirements(tmp_path / "f0.txt")
    assert result.dependencies == []
    assert any("nested more than" in i.message for i in result.issues)


# -------------------------------------------------------------- encodings

def test_utf16_file_from_powershell(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_bytes("requests==2.31.0\r\nflask==3.0.0\r\n".encode("utf-16"))
    result = parse_requirements(path)
    assert [d.name for d in result.dependencies] == ["requests", "flask"]


def test_utf8_bom_file(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"\xef\xbb\xbfrequests==2.31.0\n")
    assert parse_requirements(path).dependencies[0].name == "requests"


def test_crlf_line_endings(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"requests==2.31.0\r\nflask==3.0.0\r\n")
    assert len(parse_requirements(path).dependencies) == 2


# ------------------------------------------------------------ top-level errors

def test_missing_top_level_file_raises(tmp_path):
    with pytest.raises(RequirementsError):
        parse_requirements(tmp_path / "nope.txt")


def test_binary_garbage_raises(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"\x80\x81\x82\xfa\xfb")
    with pytest.raises(RequirementsError):
        parse_requirements(path)


def test_oversized_file_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(req_module, "MAX_FILE_BYTES", 10)
    path = tmp_path / "requirements.txt"
    path.write_text("requests==2.31.0\n")
    with pytest.raises(RequirementsError, match="larger than"):
        parse_requirements(path)
