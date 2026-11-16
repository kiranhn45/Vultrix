import pytest

from valtrix.models import DependencyGraph
from valtrix.reports import render_graph
from valtrix.versions import choose_fix, parse_semver, sort_versions

A, B, C, D = (("npm", n, "1") for n in "abcd")


def lt(a, b):
    return parse_semver(a) < parse_semver(b)


def test_semver_ordering():
    ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
               "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0"]
    for earlier, later in zip(ordered, ordered[1:]):
        assert lt(earlier, later), f"{earlier} should be older than {later}"


def test_semver_details():
    assert parse_semver("v1.2.3") == parse_semver("1.2.3") == parse_semver("1.2.3+build.5")
    assert parse_semver("1.0") == parse_semver("1.0.0")
    assert lt("0.0.0-20220101000000-abcdef123456", "0.0.0-20230101000000-000000000000")   # Go pseudo-versions
    assert lt("2.0.0-next.1", "2.0.0")


@pytest.mark.parametrize("text", ["", "abc", "1.x", "1..2", None, 7, "1.0.0-", "9" * 200])
def test_semver_rejects_nonsense(text):
    assert parse_semver(text) is None


def test_choose_fix_uses_the_ecosystem_rules():
    assert choose_fix("4.17.20", ["4.17.21", "5.0.0"], "npm") == "4.17.21"
    assert choose_fix("2.0.0-next.1", ["2.0.0"], "npm") == "2.0.0"
    assert choose_fix("2.0.0", ["2.0.0-rc.1"], "crates.io") is None
    assert sort_versions(["1.10.0", "1.9.0", "junk"], "Go") == ("1.9.0", "1.10.0", "junk")


def test_shortest_path_and_reachability():
    graph = DependencyGraph()
    graph.add_root(A)
    graph.add_edge(A, B)
    graph.add_edge(B, C)
    graph.add_edge(A, C)            # a shorter way to c
    graph.add_edge(D, C)            # d is not reachable from the root
    paths = graph.shortest_paths()
    assert paths[A] == (A,) and paths[C] == (A, C) and D not in paths
    assert graph.reachable([A]) == {A, B, C}
    assert set(graph.nodes) == {A, B, C, D}


def test_cycles_do_not_hang():
    graph = DependencyGraph()
    graph.add_root(A)
    graph.add_edge(A, B)
    graph.add_edge(B, A)
    graph.add_edge(A, A)            # a self-loop is dropped
    assert graph.reachable([A]) == {A, B}
    assert graph.shortest_paths()[B] == (A, B)
    assert render_graph(graph).splitlines()[:2] == ["a 1", "  b 1"]


def test_render_marks_repeats_and_limits_output():
    graph = DependencyGraph()
    for root in (A, D):
        graph.add_root(root)
        graph.add_edge(root, B)
    graph.add_edge(B, C)
    text = render_graph(graph)
    assert text.count("c 1") == 1 and "b 1  (shown above)" in text
    assert "stopped after 2 lines" in render_graph(graph, max_lines=2)
