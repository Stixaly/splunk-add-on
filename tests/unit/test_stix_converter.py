"""Unit tests for the STIX bundles produced by the alert actions."""
import json

import pytest
import stix2

import stix_converter
from stix_converter import FAKE_INDICATOR_ID, STIX_PATTERNS, convert_to_sighting
from utils import generate_indicator_id

AUTHOR = stix2.Identity(
    id="identity--11111111-1111-4111-8111-111111111111",
    name="test", identity_class="system")

SAMPLE_VALUES = {
    "ipv4": "198.51.100.7",
    "ipv6": "2001:db8::1",
    "domain": "evil.test",
    "url": "http://evil.test/a",
    "hostname": "WKS-001",
    "email_addr": "a@evil.test",
    "user_agent": "Mozilla/5.0",
    "file_name": "invoice.exe",
    "md5": "d" * 32,
    "sha1": "e" * 40,
    "sha256": "f" * 64,
    "sha512": "a" * 128,
}


def objects_of(bundle, stix_type):
    return [o for o in bundle["objects"] if o["type"] == stix_type]


def build(sighting_params, alert_event, **overrides):
    return json.loads(convert_to_sighting(sighting_params(**overrides), alert_event))


# --------------------------------------------------------------------------
# pattern building
# --------------------------------------------------------------------------

@pytest.mark.parametrize("observable_type", sorted(STIX_PATTERNS))
def test_every_pattern_type_has_a_sample(observable_type):
    """Guards the table below against a type being added without a test."""
    assert observable_type in SAMPLE_VALUES


@pytest.mark.parametrize("observable_type, expected", [
    ("ipv4", "[ipv4-addr:value = '198.51.100.7']"),
    ("domain", "[domain-name:value = 'evil.test']"),
    ("md5", "[file:hashes.'MD5' = '%s']" % ("d" * 32)),
    ("sha256", "[file:hashes.'SHA-256' = '%s']" % ("f" * 64)),
    ("file_name", "[file:name = 'invoice.exe']"),
])
def test_build_stix_pattern(observable_type, expected):
    assert stix_converter._build_stix_pattern(
        observable_type, SAMPLE_VALUES[observable_type]) == expected


@pytest.mark.parametrize("value, expected", [
    ("in'voice.exe", r"[file:name = 'in\'voice.exe']"),
    (r"C:\Temp\evil.exe", r"[file:name = 'C:\\Temp\\evil.exe']"),
])
def test_build_stix_pattern_escapes_the_value(value, expected):
    assert stix_converter._build_stix_pattern("file_name", value) == expected


def test_build_stix_pattern_rejects_an_unknown_type():
    with pytest.raises(Exception, match="Unable to build a STIX pattern"):
        stix_converter._build_stix_pattern("banana", "x")


# --------------------------------------------------------------------------
# observable conversion
# --------------------------------------------------------------------------

@pytest.mark.parametrize("observable_type, value, stix_type", [
    ("ipv4", "198.51.100.7", "ipv4-addr"),
    ("ipv6", "2001:db8::1", "ipv6-addr"),
    ("url", "http://evil.test/a", "url"),
    ("domain", "evil.test", "domain-name"),
    ("hostname", "WKS-001", "hostname"),
    ("md5", "d" * 32, "file"),
    ("sha256", "f" * 64, "file"),
    ("file_name", "invoice.exe", "file"),
    ("email_addr", "a@evil.test", "email-addr"),
    ("email_message", "invoice", "email-message"),
    ("user_agent", "Mozilla/5.0", "user-agent"),
    ("mutex", "evil_mutex", "mutex"),
    ("text", "a note", "text"),
    ("windows_registry_key", "HKLM\\Run", "windows-registry-key"),
    ("directory", "/tmp/evil", "directory"),
    ("mac_addr", "00:11:22:33:44:55", "mac-addr"),
    ("user_account", "jdoe", "user-account"),
])
def test_observable_conversion_produces_a_valid_object(observable_type, value, stix_type):
    """Every branch has to build an object, none may raise or be dropped."""
    converted = stix_converter._convert_observables_to_stix(
        observables=[{"type": observable_type, "value": value}],
        marking=stix2.TLP_AMBER,
        creator=AUTHOR,
    )
    assert len(converted) == 1, "observable was dropped"
    assert converted[0].type == stix_type


def test_unknown_observable_type_is_dropped_without_raising():
    assert stix_converter._convert_observables_to_stix(
        observables=[{"type": "banana", "value": "x"}],
        marking=stix2.TLP_AMBER, creator=AUTHOR) == []


# --------------------------------------------------------------------------
# sightings on an indicator
# --------------------------------------------------------------------------

def test_sighting_on_an_existing_indicator_id(sighting_params, alert_event):
    indicator_id = "indicator--3ae0b0a2-7289-5fda-8a85-02d057ba0968"
    bundle = build(sighting_params, alert_event,
                   sighting_of_type="indicator", sighting_of_value=indicator_id)
    sighting = objects_of(bundle, "sighting")[0]

    assert sighting["sighting_of_ref"] == indicator_id
    assert sighting["sighting_of_ref"] != FAKE_INDICATOR_ID
    assert "x_opencti_sighting_of_ref" not in sighting
    assert objects_of(bundle, "indicator") == [], "the indicator must not be duplicated"


def test_sighting_on_an_indicator_built_from_a_value(sighting_params, alert_event):
    bundle = build(sighting_params, alert_event,
                   sighting_of_type="ipv4_indicator", sighting_of_value="198.51.100.7")
    indicator = objects_of(bundle, "indicator")[0]
    sighting = objects_of(bundle, "sighting")[0]

    assert indicator["pattern"] == "[ipv4-addr:value = '198.51.100.7']"
    assert indicator["id"] == generate_indicator_id(indicator["pattern"]), \
        "the id must be the one OpenCTI computes, so the sighting joins the existing indicator"
    assert sighting["sighting_of_ref"] == indicator["id"]


def test_sighting_on_an_indicator_links_the_observable(sighting_params, alert_event):
    bundle = build(sighting_params, alert_event,
                   sighting_of_type="ipv4_indicator", sighting_of_value="198.51.100.7")
    indicator = objects_of(bundle, "indicator")[0]
    observable = objects_of(bundle, "ipv4-addr")[0]
    relationship = objects_of(bundle, "relationship")[0]

    assert relationship["relationship_type"] == "based-on"
    assert relationship["source_ref"] == indicator["id"]
    assert relationship["target_ref"] == observable["id"]


@pytest.mark.parametrize("observable_type", sorted(STIX_PATTERNS))
def test_every_indicator_type_builds_a_bundle(sighting_params, alert_event, observable_type):
    bundle = build(sighting_params, alert_event,
                   sighting_of_type=observable_type + "_indicator",
                   sighting_of_value=SAMPLE_VALUES[observable_type])
    indicator = objects_of(bundle, "indicator")[0]
    sighting = objects_of(bundle, "sighting")[0]
    assert sighting["sighting_of_ref"] == indicator["id"]


def test_sighting_accepts_a_raw_pattern(sighting_params, alert_event):
    pattern = "[ipv4-addr:value = '198.51.100.7']"
    bundle = build(sighting_params, alert_event,
                   sighting_of_type="indicator", sighting_of_value=pattern)
    indicator = objects_of(bundle, "indicator")[0]
    assert indicator["pattern"] == pattern
    assert indicator["id"] == generate_indicator_id(pattern)


# --------------------------------------------------------------------------
# sightings on an observable, the behaviour of the earlier versions
# --------------------------------------------------------------------------

@pytest.mark.parametrize("observable_type, stix_type", [
    ("ipv4_observable", "ipv4-addr"),
    ("ipv6_observable", "ipv6-addr"),
    ("url_observable", "url"),
    ("domain_observable", "domain-name"),
])
def test_sighting_on_an_observable_is_unchanged(
        sighting_params, alert_event, observable_type, stix_type):
    values = {"ipv4_observable": "198.51.100.7", "ipv6_observable": "2001:db8::1",
              "url_observable": "http://evil.test/a", "domain_observable": "evil.test"}
    bundle = build(sighting_params, alert_event,
                   sighting_of_type=observable_type,
                   sighting_of_value=values[observable_type])
    sighting = objects_of(bundle, "sighting")[0]
    observable = objects_of(bundle, stix_type)[0]

    assert sighting["sighting_of_ref"] == FAKE_INDICATOR_ID
    assert sighting["x_opencti_sighting_of_ref"] == observable["id"]
    assert objects_of(bundle, "indicator") == []


# --------------------------------------------------------------------------
# shared behaviour and failures
# --------------------------------------------------------------------------

@pytest.mark.parametrize("sighting_of_type, sighting_of_value", [
    ("indicator", "indicator--3ae0b0a2-7289-5fda-8a85-02d057ba0968"),
    ("ipv4_indicator", "198.51.100.7"),
    ("ipv4_observable", "198.51.100.7"),
])
def test_sighting_carries_the_labels(sighting_params, alert_event,
                                     sighting_of_type, sighting_of_value):
    bundle = build(sighting_params, alert_event,
                   sighting_of_type=sighting_of_type,
                   sighting_of_value=sighting_of_value,
                   labels=["alpha", "beta", "gamma"])
    assert objects_of(bundle, "sighting")[0]["labels"] == ["alpha", "beta", "gamma"]


@pytest.mark.parametrize("where_sighted_type", ["system", "organization"])
def test_where_sighted_is_added(sighting_params, alert_event, where_sighted_type):
    bundle = build(sighting_params, alert_event, where_sighted_type=where_sighted_type)
    identities = objects_of(bundle, "identity")
    assert any(i["identity_class"] == where_sighted_type for i in identities)


def test_invalid_sighting_of_type_raises(sighting_params, alert_event):
    """An unknown type used to give a bundle with no sighting and no error."""
    with pytest.raises(Exception, match="Invalid sighting_of_type"):
        build(sighting_params, alert_event, sighting_of_type="banana")


def test_invalid_where_sighted_type_raises(sighting_params, alert_event):
    with pytest.raises(Exception, match="Invalid where_sighted_type"):
        build(sighting_params, alert_event, where_sighted_type="banana")


def test_every_bundle_contains_exactly_one_sighting(sighting_params, alert_event):
    for sighting_of_type, value in [("indicator", "indicator--3ae0b0a2-7289-5fda-8a85-02d057ba0968"),
                                    ("sha256_indicator", "f" * 64),
                                    ("url_observable", "http://evil.test/a")]:
        bundle = build(sighting_params, alert_event,
                       sighting_of_type=sighting_of_type, sighting_of_value=value)
        assert len(objects_of(bundle, "sighting")) == 1


# --------------------------------------------------------------------------
# count and time window of a sighting
# --------------------------------------------------------------------------

def sighting_of(bundle):
    return objects_of(bundle, "sighting")[0]


def test_sighting_count_defaults_to_one(sighting_params, alert_event):
    assert sighting_of(build(sighting_params, alert_event))["count"] == 1


@pytest.mark.parametrize("count, expected", [("12", 12), (" 7 ", 7), (3, 3), ("", 1), (None, 1)])
def test_sighting_carries_the_count(sighting_params, alert_event, count, expected):
    bundle = build(sighting_params, alert_event, count=count)
    assert sighting_of(bundle)["count"] == expected


@pytest.mark.parametrize("count", ["twelve", "12.5", "-3"])
def test_an_invalid_count_is_an_error(sighting_params, alert_event, count):
    with pytest.raises(Exception, match="Invalid count"):
        build(sighting_params, alert_event, count=count)


def test_sighting_window_defaults_to_the_event_time(sighting_params, alert_event):
    """Without an explicit window the sighting is the instant of the event,
    which is the behaviour of the earlier versions."""
    sighting = sighting_of(build(sighting_params, alert_event))
    assert sighting["first_seen"] == "2025-08-08T08:00:00Z"
    assert sighting["last_seen"] == "2025-08-08T08:00:00Z"


def test_sighting_window_defaults_to_now_without_an_event_time(sighting_params):
    from datetime import datetime, timezone

    sighting = sighting_of(build(sighting_params, {"host": "splunk-search-01"}))
    first_seen = datetime.strptime(sighting["first_seen"], "%Y-%m-%dT%H:%M:%S.%fZ") \
        if "." in sighting["first_seen"] else datetime.strptime(sighting["first_seen"], "%Y-%m-%dT%H:%M:%SZ")
    first_seen = first_seen.replace(tzinfo=timezone.utc)
    assert abs((datetime.now(timezone.utc) - first_seen).total_seconds()) < 60
    assert sighting["last_seen"] == sighting["first_seen"]


def test_sighting_carries_the_window(sighting_params, alert_event):
    """min(_time) and max(_time) of a stats search give epoch seconds."""
    sighting = sighting_of(build(sighting_params, alert_event,
                                 first_seen="1754600000", last_seen="1754640000"))
    assert sighting["first_seen"] == "2025-08-07T20:53:20Z"
    assert sighting["last_seen"] == "2025-08-08T08:00:00Z"


def test_sighting_window_accepts_iso_dates(sighting_params, alert_event):
    sighting = sighting_of(build(sighting_params, alert_event,
                                 first_seen="2025-08-07T20:53:20Z",
                                 last_seen="2025-08-08T10:00:00+02:00"))
    assert sighting["first_seen"] == "2025-08-07T20:53:20Z"
    assert sighting["last_seen"] == "2025-08-08T08:00:00Z"


@pytest.mark.parametrize("given", ["first_seen", "last_seen"])
def test_a_window_with_one_end_is_read_as_that_instant(sighting_params, alert_event, given):
    sighting = sighting_of(build(sighting_params, alert_event, **{given: "1754600000"}))
    assert sighting["first_seen"] == "2025-08-07T20:53:20Z"
    assert sighting["last_seen"] == "2025-08-07T20:53:20Z"


def test_a_reversed_window_is_an_error(sighting_params, alert_event):
    """stix2 would reject it too, but with a message naming no parameter."""
    with pytest.raises(Exception, match="Invalid sighting dates"):
        build(sighting_params, alert_event, first_seen="1754640000", last_seen="1754600000")


@pytest.mark.parametrize("given", ["first_seen", "last_seen"])
def test_an_unreadable_date_is_an_error(sighting_params, alert_event, given):
    with pytest.raises(Exception, match="Invalid date"):
        build(sighting_params, alert_event, **{given: "yesterday"})


def test_the_window_and_the_count_do_not_change_the_sighting_id(sighting_params, alert_event):
    """Every run of the alert for the same indicator on the same system has to
    land on the same sighting in OpenCTI, whatever the window reported."""
    plain = sighting_of(build(sighting_params, alert_event))
    aggregated = sighting_of(build(sighting_params, alert_event, count="40",
                                   first_seen="1754600000", last_seen="1754640000"))
    assert aggregated["id"] == plain["id"]


def test_the_window_does_not_move_the_indicator_valid_from(sighting_params, alert_event):
    """The indicator is only referenced, its own dates stay those of the event."""
    bundle = build(sighting_params, alert_event, first_seen="1754600000", last_seen="1754640000")
    assert objects_of(bundle, "indicator")[0]["valid_from"] == "2025-08-08T08:00:00Z"


# --------------------------------------------------------------------------
# score and validity given to the sighted indicator
# --------------------------------------------------------------------------

INDICATOR_ID = "indicator--3ae0b0a2-7289-5fda-8a85-02d057ba0968"


def test_the_bundled_indicator_is_left_alone_by_default(sighting_params, alert_event):
    indicator = objects_of(build(sighting_params, alert_event), "indicator")[0]
    assert "x_opencti_score" not in indicator
    assert "valid_until" not in indicator


def test_the_bundled_indicator_carries_the_score(sighting_params, alert_event):
    bundle = build(sighting_params, alert_event, indicator_score="100")
    assert objects_of(bundle, "indicator")[0]["x_opencti_score"] == 100


def test_the_bundled_indicator_validity_is_counted_from_last_seen(sighting_params, alert_event):
    bundle = build(sighting_params, alert_event,
                   first_seen="1754600000", last_seen="1754640000", indicator_validity_days="90")
    indicator = objects_of(bundle, "indicator")[0]
    assert indicator["valid_until"] == "2025-11-06T08:00:00Z", "2025-08-08 plus 90 days"
    assert indicator["valid_from"] == "2025-08-08T08:00:00Z"


def test_the_bundled_indicator_validity_defaults_to_the_event_time_plus_the_days(
        sighting_params, alert_event):
    bundle = build(sighting_params, alert_event, indicator_validity_days="90")
    assert objects_of(bundle, "indicator")[0]["valid_until"] == "2025-11-06T08:00:00Z"


def test_a_validity_ending_before_valid_from_is_an_error(sighting_params, alert_event):
    """valid_from is the event time, a window ending before it cannot give a
    valid_until after it. stix2 would refuse the indicator with its own words."""
    with pytest.raises(Exception, match="Invalid indicator validity"):
        build(sighting_params, alert_event, last_seen="1754500000", indicator_validity_days="1")


@pytest.mark.parametrize("sighting_of_type, sighting_of_value", [
    ("indicator", INDICATOR_ID),
    ("ipv4_observable", "198.51.100.7"),
])
def test_score_and_validity_add_no_indicator_to_the_bundle(sighting_params, alert_event,
                                                          sighting_of_type, sighting_of_value):
    """A referenced indicator is refreshed through the API, an observable
    sighting has no indicator: neither must gain one in the bundle."""
    bundle = build(sighting_params, alert_event,
                   sighting_of_type=sighting_of_type, sighting_of_value=sighting_of_value,
                   indicator_score="100", indicator_validity_days="90")
    assert objects_of(bundle, "indicator") == []
    assert len(objects_of(bundle, "sighting")) == 1


def test_an_invalid_score_is_an_error(sighting_params, alert_event):
    with pytest.raises(Exception, match="Invalid score"):
        build(sighting_params, alert_event, indicator_score="150")


def test_an_invalid_validity_is_an_error(sighting_params, alert_event):
    with pytest.raises(Exception, match="Invalid number of days"):
        build(sighting_params, alert_event, indicator_validity_days="0")


# --------------------------------------------------------------------------
# sighting_target_of
# --------------------------------------------------------------------------

def test_sighting_target_of_an_indicator_built_from_a_value(sighting_params, alert_event):
    from datetime import datetime, timezone

    bundle = convert_to_sighting(sighting_params(last_seen="1754640000"), alert_event)
    indicator_id, last_seen = stix_converter.sighting_target_of(bundle)
    assert indicator_id == generate_indicator_id("[ipv4-addr:value = '198.51.100.7']")
    assert last_seen == datetime(2025, 8, 8, 8, tzinfo=timezone.utc)


def test_sighting_target_of_a_referenced_indicator(sighting_params, alert_event):
    bundle = convert_to_sighting(
        sighting_params(sighting_of_type="indicator", sighting_of_value=INDICATOR_ID), alert_event)
    assert stix_converter.sighting_target_of(bundle)[0] == INDICATOR_ID


def test_sighting_target_of_an_observable_sighting_is_none(sighting_params, alert_event):
    bundle = convert_to_sighting(
        sighting_params(sighting_of_type="ipv4_observable", sighting_of_value="198.51.100.7"),
        alert_event)
    assert stix_converter.sighting_target_of(bundle) is None


def test_sighting_target_of_a_bundle_without_sighting_is_none():
    assert stix_converter.sighting_target_of(json.dumps({"objects": []})) is None
