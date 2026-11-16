"""Parsers for lock files and other ecosystems, and project discovery."""

import json
from pathlib import Path

import pytest

from valtrix.models import CARGO, GO, NPM, PYPI
from valtrix.parsers import ParseError, discover
from valtrix.parsers.cargo import parse_cargo_lock
from valtrix.parsers.gomod import parse_go_mod
from valtrix.parsers.npm import parse_package_lock
from valtrix.parsers.python_project import (
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pyproject,
    parse_uv_lock,
    read_pyproject,
)

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def by_name(deps):
    return {d.name: d for d in deps}


def write(folder, name, text):
    path = folder / name
    path.write_text(text, encoding="utf-8")
    return path


# ------------------------------------------------------------ pyproject.toml

PYPROJECT = """
[project]
name = "demo"
dependencies = ["Django==3.2.0", "requests>=2.25", "flask[async]==2.0.1 ; python_version > '3.8'"]

[project.optional-dependencies]
socks = ["pysocks==1.7.1"]
test = ["pytest==7.0.0"]

[dependency-groups]
dev = ["ruff==0.1.0", {include-group = "other"}]
"""


def test_pyproject_dependencies_and_dev_groups(tmp_path):
    result = parse_pyproject(write(tmp_path, "pyproject.toml", PYPROJECT), "pyproject.toml")
    deps = by_name(result.dependencies)
    assert deps["django"].version == "3.2.0" and deps["django"].direct is True
    assert deps["requests"].version is None and deps["requests"].specifier == ">=2.25"
    assert deps["flask"].extras == ("async",) and deps["flask"].marker
    assert deps["pysocks"].dev is False          # an ordinary extra ships with the product
    assert deps["pytest"].dev is True and deps["ruff"].dev is True
    assert deps["django"].line == 4              # points at the line in the file


def test_pyproject_poetry_tables(tmp_path):
    path = write(tmp_path, "pyproject.toml", """
[tool.poetry.dependencies]
python = "^3.11"
flask = "2.0.1"
requests = "^2.25"
local = {path = "../local"}
[tool.poetry.group.dev.dependencies]
black = {version = "==23.1.0"}
""")
    deps = by_name(parse_pyproject(path, "pyproject.toml").dependencies)
    assert "python" not in deps
    assert deps["flask"].version == "2.0.1"
    assert deps["requests"].version is None and deps["requests"].specifier == "^2.25"
    assert deps["local"].specifier.startswith("@")
    assert deps["black"].version == "23.1.0" and deps["black"].dev


def test_pyproject_production_wins_over_dev(tmp_path):
    path = write(tmp_path, "pyproject.toml",
                 '[project]\ndependencies=["a==1"]\n[dependency-groups]\ndev=["a==1","b==1"]\n')
    assert read_pyproject(path).direct == {"a": False, "b": True}


@pytest.mark.parametrize("text", ["[project\n", "\x00\x01", "project = 5\n[project]\n"])
def test_broken_toml_is_bad_input(tmp_path, text):
    with pytest.raises(ParseError, match="not valid TOML"):
        read_pyproject(write(tmp_path, "pyproject.toml", text))


def test_pyproject_with_wrong_types_does_not_crash(tmp_path):
    path = write(tmp_path, "pyproject.toml",
                 'project = "x"\ntool = 3\n[dependency-groups]\ndev = "oops"\n')
    assert parse_pyproject(path, "pyproject.toml").dependencies == []


# ----------------------------------------------------------------- lock files

def test_poetry_lock_example_has_graph_and_dev():
    project = discover(EXAMPLES / "poetry-app")
    deps = by_name(project.dependencies)
    assert project.sources == ["poetry.lock"]
    assert deps["flask"].direct is True and deps["flask"].path == ()
    assert deps["markupsafe"].direct is False
    assert deps["markupsafe"].path == ("flask 2.0.1", "jinja2 3.0.1", "markupsafe 2.0.1")
    assert deps["pyyaml"].dev is True and deps["requests"].dev is False
    assert deps["flask"].line > 1                # line of the [[package]] entry
    assert all(d.ecosystem == PYPI and d.version for d in project.dependencies)


def test_poetry_lock_without_pyproject_does_not_guess(tmp_path):
    lock = (EXAMPLES / "poetry-app" / "poetry.lock").read_text()
    result = parse_poetry_lock(write(tmp_path, "poetry.lock", lock), "poetry.lock", None)
    assert all(d.direct is None for d in result.dependencies)
    assert result.edges                           # the tree is still recorded


def test_dev_only_transitive_dependencies_are_marked(tmp_path):
    write(tmp_path, "pyproject.toml",
          '[tool.poetry.dependencies]\na = "*"\n[tool.poetry.group.dev.dependencies]\nb = "*"\n')
    write(tmp_path, "poetry.lock", """
[[package]]
name = "a"
version = "1"
[package.dependencies]
shared = "*"
[[package]]
name = "b"
version = "1"
[package.dependencies]
shared = "*"
only-dev = "*"
[[package]]
name = "shared"
version = "1"
[[package]]
name = "only-dev"
version = "1"
""")
    deps = by_name(discover(tmp_path).dependencies)
    assert deps["only-dev"].dev is True
    assert deps["shared"].dev is False            # also reachable from production


def test_poetry_lock_skips_unusable_entries(tmp_path):
    path = write(tmp_path, "poetry.lock",
                 '[[package]]\nname = "ok"\nversion = "1.0"\n[[package]]\nname = "../evil"\nversion = "1"\n'
                 '[[package]]\nname = "nover"\n')
    result = parse_poetry_lock(path, "poetry.lock")
    assert [d.name for d in result.dependencies] == ["ok"]
    assert len(result.issues) == 2


def test_uv_lock_example():
    project = discover(EXAMPLES / "uv-app")
    deps = by_name(project.dependencies)
    assert set(deps) == {"jinja2", "markupsafe", "pyyaml"}     # the project itself is not a dependency
    assert deps["jinja2"].direct is True and deps["markupsafe"].direct is False
    assert deps["markupsafe"].path == ("jinja2 3.0.1", "markupsafe 2.0.1")
    assert deps["pyyaml"].dev is True


def test_uv_lock_without_root_package(tmp_path):
    path = write(tmp_path, "uv.lock", '[[package]]\nname = "a"\nversion = "1.0"\nsource = { registry = "x" }\n')
    assert parse_uv_lock(path, "uv.lock").dependencies[0].direct is None


def test_pipfile_lock(tmp_path):
    path = write(tmp_path, "Pipfile.lock", json.dumps({
        "default": {"Django": {"version": "==3.2.0"}, "mylib": {"git": "https://example.com/x.git"}},
        "develop": {"pytest": {"version": "==7.0.0"}},
    }, indent=4))
    deps = by_name(parse_pipfile_lock(path, "Pipfile.lock", {"django": False}).dependencies)
    assert deps["django"].version == "3.2.0" and deps["django"].direct is True
    assert deps["pytest"].dev is True and deps["pytest"].direct is False
    assert deps["mylib"].version is None


def test_pipfile_lock_must_be_an_object(tmp_path):
    with pytest.raises(ParseError, match="JSON"):
        parse_pipfile_lock(write(tmp_path, "Pipfile.lock", "[1, 2]"), "Pipfile.lock")


# ------------------------------------------------------------------------ npm

def test_package_lock_example():
    project = discover(EXAMPLES / "node-app")
    deps = by_name(project.dependencies)
    assert all(d.ecosystem == NPM for d in project.dependencies)
    assert deps["express"].direct is True and deps["qs"].direct is False
    assert deps["qs"].path == ("express 4.17.1", "qs 6.7.0")     # the shortest chain
    assert deps["minimist"].dev is True
    assert deps["lodash"].line > 1


def test_package_lock_nested_versions_and_scopes(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"a": "1", "@scope/pkg": "2"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^2"}},
        "node_modules/a/node_modules/b": {"version": "2.0.0"},
        "node_modules/b": {"version": "1.0.0"},
        "node_modules/@scope/pkg": {"version": "2.0.0"},
        "node_modules/linked": {"link": True, "resolved": "packages/linked"},
        "node_modules/bad": {"version": "not a version"},
    }}
    result = parse_package_lock(write(tmp_path, "package-lock.json", json.dumps(lock)), "package-lock.json")
    found = {(d.name, d.version) for d in result.dependencies}
    assert found == {("a", "1.0.0"), ("b", "2.0.0"), ("b", "1.0.0"), ("@scope/pkg", "2.0.0")}
    # `a` gets its own nested copy of b, not the top-level one.
    assert ((NPM, "a", "1.0.0"), (NPM, "b", "2.0.0")) in result.edges
    assert len(result.issues) == 1


def test_package_lock_version_1(tmp_path):
    write(tmp_path, "package.json", json.dumps({"dependencies": {"a": "1"}, "devDependencies": {"d": "1"}}))
    lock = {"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "requires": {"b": "^1"}, "dependencies": {"b": {"version": "1.5.0"}}},
        "b": {"version": "1.0.0"},
        "d": {"version": "1.0.0", "dev": True},
    }}
    path = write(tmp_path, "package-lock.json", json.dumps(lock))
    result = parse_package_lock(path, "package-lock.json", tmp_path / "package.json")
    deps = {(d.name, d.version): d for d in result.dependencies}
    assert deps[("a", "1.0.0")].direct is True and deps[("b", "1.0.0")].direct is False
    assert deps[("d", "1.0.0")].dev is True
    assert ((NPM, "a", "1.0.0"), (NPM, "b", "1.5.0")) in result.edges


def test_package_json_without_lock_is_explained(tmp_path):
    write(tmp_path, "package.json", "{}")
    project = discover(tmp_path)
    assert project.sources == ["package.json"] and not project.dependencies
    assert "package-lock.json" in project.issues[0].message


# ------------------------------------------------------------------ Rust, Go

def test_cargo_lock_example():
    result = parse_cargo_lock(EXAMPLES / "rust-app" / "Cargo.lock", "Cargo.lock")
    deps = by_name(result.dependencies)
    assert set(deps) == {"libc", "smallvec", "time"}             # the project's own crate is left out
    assert deps["time"].direct is True and deps["libc"].direct is False
    assert ((CARGO, "time", "0.1.44"), (CARGO, "libc", "0.2.139")) in result.edges


def test_cargo_lock_two_versions_of_one_crate(tmp_path):
    path = write(tmp_path, "Cargo.lock", """
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["dup 2.0.0", "user"]
[[package]]
name = "dup"
version = "1.0.0"
source = "registry+x"
[[package]]
name = "dup"
version = "2.0.0"
source = "registry+x"
[[package]]
name = "user"
version = "1.0.0"
source = "registry+x"
dependencies = ["dup 1.0.0 (registry+x)"]
""")
    result = parse_cargo_lock(path, "Cargo.lock")
    deps = {(d.name, d.version): d for d in result.dependencies}
    assert deps[("dup", "2.0.0")].direct is True and deps[("dup", "1.0.0")].direct is False
    assert ((CARGO, "user", "1.0.0"), (CARGO, "dup", "1.0.0")) in result.edges


def test_go_mod_example():
    result = parse_go_mod(EXAMPLES / "go-app" / "go.mod", "go.mod")
    deps = by_name(result.dependencies)
    assert deps["github.com/gin-gonic/gin"].version == "1.7.0"   # the leading v is dropped
    assert deps["golang.org/x/text"].direct is False
    assert deps["gopkg.in/yaml.v2"].direct is True and deps["gopkg.in/yaml.v2"].line == 10
    assert all(d.ecosystem == GO for d in result.dependencies)


def test_go_mod_odd_lines(tmp_path):
    path = write(tmp_path, "go.mod", "module x\nrequire (\n  a.b/c v1.2.3+incompatible\n  broken\n"
                                     "  d.e/f v0.0.0-20220101000000-abcdef123456\n)\nreplace a => b v1.0.0\n")
    result = parse_go_mod(path, "go.mod")
    assert [(d.name, d.version) for d in result.dependencies] == [
        ("a.b/c", "1.2.3"), ("d.e/f", "0.0.0-20220101000000-abcdef123456")]
    assert len(result.issues) == 1 and result.issues[0].line == 4


# ------------------------------------------------------------------ discovery

def test_discover_reads_every_ecosystem_in_one_folder(tmp_path):
    for folder, name in [("node-app", "package-lock.json"), ("rust-app", "Cargo.lock"), ("go-app", "go.mod")]:
        write(tmp_path, name, (EXAMPLES / folder / name).read_text())
    write(tmp_path, "requirements.txt", "django==3.2.0\n")
    write(tmp_path, "requirements-dev.txt", "pytest==7.0.0\n")
    project = discover(tmp_path)
    assert project.sources == ["Cargo.lock", "go.mod", "package-lock.json", "requirements-dev.txt", "requirements.txt"]
    assert {d.ecosystem for d in project.dependencies} == {PYPI, NPM, CARGO, GO}
    assert by_name(project.dependencies)["pytest"].dev is True


def test_pyproject_is_only_a_source_when_nothing_pins_versions(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\ndependencies = ["django==3.2.0"]\n')
    assert discover(tmp_path).sources == ["pyproject.toml"]
    write(tmp_path, "requirements.txt", "django==3.2.0\n")
    assert discover(tmp_path).sources == ["requirements.txt"]


def test_discover_empty_folder(tmp_path):
    project = discover(tmp_path)
    assert project.sources == [] and project.dependencies == []


def test_unreadable_lock_file_is_bad_input(tmp_path):
    write(tmp_path, "package-lock.json", "{not json")
    with pytest.raises(ParseError, match="not valid JSON"):
        discover(tmp_path)


def test_deeply_nested_json_does_not_crash(tmp_path):
    write(tmp_path, "package-lock.json", "[" * 100_000)
    with pytest.raises(ParseError):
        discover(tmp_path)
