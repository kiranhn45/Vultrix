from valtrix.models import Vulnerability, merge_related


def v(id, aliases=(), **kw):
    return Vulnerability(id=id, aliases=tuple(aliases), **kw)


def test_no_input():
    assert merge_related([]) == []


def test_unrelated_records_are_untouched():
    a, b = v("GHSA-1", ["CVE-1"]), v("GHSA-2", ["CVE-2"])
    assert merge_related([a, b]) == [a, b]


def test_pair_sharing_an_identifier_is_merged():
    ghsa = v("GHSA-1", ["CVE-1", "PYSEC-1"], severity_label="HIGH", summary="Bad thing",
             fixed_versions=("3.2.13", "4.0.4"), references=("https://a.example",))
    pysec = v("PYSEC-1", ["CVE-1", "GHSA-1"], fixed_versions=("4.0.4", "2.2.28"),
              references=("https://b.example",), published="2022-01-01", modified="2022-02-01")
    [merged] = merge_related([pysec, ghsa])
    assert merged.id == "GHSA-1"
    assert merged.severity_label == "HIGH"
    assert merged.summary == "Bad thing"
    assert merged.aliases == ("CVE-1", "PYSEC-1")
    assert merged.fixed_versions == ("3.2.13", "4.0.4", "2.2.28")
    assert merged.references == ("https://a.example", "https://b.example")
    assert merged.published == "2022-01-01" and merged.modified == "2022-02-01"


def test_record_with_severity_wins_over_preferred_prefix():
    cve = v("CVE-1", ["PYSEC-1"], severity_label="LOW")
    ghsa = v("GHSA-1", ["PYSEC-1"])
    assert merge_related([ghsa, cve])[0].id == "CVE-1"


def test_chains_are_merged_transitively():
    a, b, c = v("A-1", ["CVE-1"]), v("B-1", ["CVE-1", "CVE-2"]), v("C-1", ["CVE-2"])
    assert len(merge_related([a, b, c])) == 1


def test_no_identifier_is_lost():
    merged = merge_related([v("GHSA-1", ["CVE-1", "BIT-1"]), v("PYSEC-1", ["CVE-1", "OTHER-9"])])[0]
    everything = {merged.id, *merged.aliases}
    assert everything == {"GHSA-1", "CVE-1", "BIT-1", "PYSEC-1", "OTHER-9"}


def test_order_follows_first_appearance():
    a, b, c = v("X-1", ["CVE-1"]), v("Y-1", ["CVE-2"]), v("Z-1", ["CVE-1"])
    result = merge_related([a, b, c])
    assert [r.id for r in result] == ["X-1", "Y-1"]


def test_inputs_are_not_modified():
    a, b = v("GHSA-1", ["CVE-1"]), v("PYSEC-1", ["CVE-1"])
    merge_related([a, b])
    assert a.aliases == ("CVE-1",) and b.aliases == ("CVE-1",)
