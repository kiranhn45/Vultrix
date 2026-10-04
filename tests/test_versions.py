import itertools

import pytest

from valtrix.versions import choose_fix, parse_version, sort_versions


def lt(a, b):
    return parse_version(a) < parse_version(b)


# PEP 440 ordering, oldest to newest.
ORDERED = [
    "1.0.dev1", "1.0a1", "1.0a2.dev1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0+local",
    "1.0.post1.dev1", "1.0.post1", "1.0.1", "1.1", "1.10", "2.0", "1!0.5",
]


def test_documented_ordering():
    for earlier, later in zip(ORDERED, ORDERED[1:]):
        assert lt(earlier, later), f"{earlier} should be older than {later}"


def test_numeric_not_text_comparison():
    assert lt("3.2.9", "3.2.10")
    assert lt("2.9", "2.10")


def test_trailing_zeros_are_equal():
    assert parse_version("1.0") == parse_version("1.0.0") == parse_version("1")


def test_spelling_variants_are_equal():
    assert parse_version("1.0alpha1") == parse_version("1.0a1")
    assert parse_version("1.0-rc.1") == parse_version("1.0rc1")
    assert parse_version("v1.0") == parse_version("1.0")
    assert parse_version("1.0-1") == parse_version("1.0.post1")


@pytest.mark.parametrize("text", ["", "abc", "1.x", "1..0", "1.0 beta", None, 5, "9" * 200])
def test_unparseable_returns_none(text):
    assert parse_version(text) is None


def test_matches_packaging_library():
    """Cross-check every pair against the reference implementation."""
    packaging_version = pytest.importorskip("packaging.version")
    samples = ORDERED + [
        "0.9", "1.0.0", "1.0rc2", "1.0.post2", "1.0.dev0", "2.0.0a1", "2.2.28", "3.2", "3.2.0",
        "3.2.13", "4.0.4", "5.2.17", "6.0.8", "1.0+abc", "1.0+abc.5", "1.0+5", "1.0.post1+x",
        "2024.1", "2024.01.1", "0.0.1", "10.0.0b2", "1.2.3.4.5",
    ]
    for a, b in itertools.product(samples, repeat=2):
        ours, theirs = parse_version(a), parse_version(b)
        ref_a, ref_b = packaging_version.Version(a), packaging_version.Version(b)
        assert (ours < theirs) == (ref_a < ref_b), (a, b)
        assert (ours == theirs) == (ref_a == ref_b), (a, b)


# ------------------------------------------------------------- choose_fix

def test_picks_fix_on_same_release_line():
    # The case seen with django 3.2.0: one fix per release line.
    assert choose_fix("3.2.0", ["2.2.28", "3.2.13", "4.0.4"]) == "3.2.13"


def test_ignores_fixes_older_than_installed():
    assert choose_fix("3.2.0", ["2.2.28", "3.1.13"]) is None


def test_lowest_on_the_same_line():
    assert choose_fix("3.2.0", ["3.2.25", "3.2.4", "3.2.13"]) == "3.2.4"


def test_falls_back_to_same_major_then_lowest_above():
    assert choose_fix("3.2.0", ["3.9.1", "4.2.1", "5.0.0"]) == "3.9.1"
    assert choose_fix("3.2.0", ["5.2.16", "6.0.7"]) == "5.2.16"


def test_installed_equal_to_fix_is_not_a_fix():
    assert choose_fix("3.2.13", ["3.2.13"]) is None


def test_unparseable_inputs_give_none():
    assert choose_fix("not-a-version", ["1.0"]) is None
    assert choose_fix("1.0", ["garbage", "also bad"]) is None
    assert choose_fix("1.0", []) is None


def test_garbage_entries_are_skipped_not_fatal():
    assert choose_fix("1.0.0", ["junk", "1.0.5"]) == "1.0.5"


def test_sort_versions():
    assert sort_versions(["4.0.4", "2.2.28", "3.2.13"]) == ("2.2.28", "3.2.13", "4.0.4")
    assert sort_versions(["3.2.10", "3.2.9"]) == ("3.2.9", "3.2.10")
    assert sort_versions(["zzz", "1.0", "abc"]) == ("1.0", "zzz", "abc")


# Fixed-version lists copied from a real OSV response for django 3.2.0.
@pytest.mark.parametrize(
    "fixed, expected",
    [
        (["2.2.28", "3.2.13", "4.0.4"], "3.2.13"),
        (["3.2.5", "3.1.13"], "3.2.5"),                  # newer line listed after an older one
        (["5.2.16", "6.0.7"], "5.2.16"),                 # nothing on the 3.2 line, smallest jump
        (["4.2.24", "5.1.12", "5.2.6"], "4.2.24"),
        (["5.1.1", "5.0.9", "4.2.16"], "4.2.16"),        # unsorted input
        (["5.2.2", "5.1.10", "4.2.22"], "4.2.22"),
        (["2.2.21", "3.1.9", "3.2.1"], "3.2.1"),
    ],
)
def test_real_django_fix_lists(fixed, expected):
    assert choose_fix("3.2.0", fixed) == expected
