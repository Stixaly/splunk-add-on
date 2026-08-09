"""Unit tests for the shared helpers, mostly the deterministic STIX ids."""
import datetime

import pytest

import utils


# --------------------------------------------------------------------------
# address and hash detection
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value, expected", [
    ("198.51.100.7", True),
    ("0.0.0.0", True),
    ("198.51.100.0/24", True),
    ("2001:db8::1", False),
    ("not an address", False),
    ("", False),
])
def test_is_ipv4(value, expected):
    assert utils.is_ipv4(value) is expected


@pytest.mark.parametrize("value, expected", [
    ("2001:db8::1", True),
    ("::1", True),
    ("2001:db8::/32", True),
    ("198.51.100.7", False),
    ("not an address", False),
])
def test_is_ipv6(value, expected):
    assert utils.is_ipv6(value) is expected


@pytest.mark.parametrize("value, expected", [
    ("d" * 32, "md5"),
    ("e" * 40, "sha1"),
    ("f" * 64, "sha256"),
    ("a" * 128, "sha512"),
    ("nope", None),
])
def test_get_hash_type(value, expected):
    assert utils.get_hash_type(value) == expected


# --------------------------------------------------------------------------
# deterministic identifiers
# --------------------------------------------------------------------------

OPENCTI_NAMESPACE_CASES = [
    (utils.generate_indicator_id, ("[ipv4-addr:value = '198.51.100.7']",), "indicator--"),
    (utils.generate_identity_id, ("Splunk", "system"), "identity--"),
    (utils.generate_case_incident_id, ("a case", "2026-01-01T00:00:00"), "case-incident--"),
    (utils.generate_incident_id, ("an incident", "2026-01-01T00:00:00"), "incident--"),
]


@pytest.mark.parametrize("function, args, prefix", OPENCTI_NAMESPACE_CASES)
def test_identifier_has_the_expected_prefix(function, args, prefix):
    assert function(*args).startswith(prefix)


@pytest.mark.parametrize("function, args, prefix", OPENCTI_NAMESPACE_CASES)
def test_identifier_is_stable(function, args, prefix):
    """The same input always gives the same id, which is what lets the add-on
    attach to an object already on the platform instead of duplicating it."""
    assert function(*args) == function(*args)


def test_indicator_id_matches_the_opencti_algorithm():
    """OpenCTI derives an indicator id from a uuid5 of the canonical pattern.

    The expected value is the one OpenCTI computes for this pattern, so a
    change to the algorithm is caught here.
    """
    pattern = "[ipv4-addr:value = '198.51.100.7']"
    assert utils.generate_indicator_id(pattern) == "indicator--3ae0b0a2-7289-5fda-8a85-02d057ba0968"


def test_indicator_id_depends_on_the_pattern():
    assert (utils.generate_indicator_id("[url:value = 'http://a.test/']")
            != utils.generate_indicator_id("[url:value = 'http://b.test/']"))


def test_identity_id_ignores_case_and_padding():
    assert utils.generate_identity_id("  SPLUNK ", "System") == utils.generate_identity_id("splunk", "system")


def test_sighting_id_depends_on_both_ends():
    first = utils.generate_sighting_id("indicator--a", "identity--x")
    second = utils.generate_sighting_id("indicator--a", "identity--y")
    assert first != second
    assert first == utils.generate_sighting_id("indicator--a", "identity--x")


def test_sighting_id_takes_the_dates_into_account():
    without = utils.generate_sighting_id("indicator--a", "identity--x")
    with_dates = utils.generate_sighting_id(
        "indicator--a", "identity--x",
        datetime.datetime(2026, 1, 1), datetime.datetime(2026, 1, 2))
    assert without != with_dates


def test_relation_id_depends_on_the_direction():
    forward = utils.generate_relation_id("based-on", "indicator--a", "file--b")
    backward = utils.generate_relation_id("based-on", "file--b", "indicator--a")
    assert forward != backward
