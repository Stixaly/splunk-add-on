"""Unit tests for the incident and incident response alert actions, and for
the two ways they extract observables out of a Splunk event."""
import json

import pytest
import stix2

import stix_converter
from stix_converter import (
    convert_to_incident,
    convert_to_incident_response,
)

AUTHOR = stix2.Identity(
    id="identity--11111111-1111-4111-8111-111111111111",
    name="test", identity_class="system")


def types_of(observables):
    return sorted(observable.type for observable in observables)


def extract_cim(event):
    return stix_converter._extract_observables_from_cim_model(
        event=event, marking=stix2.TLP_AMBER, creator=AUTHOR)


def extract_fields(event):
    return stix_converter._extract_observables_from_key_model(
        event=event, marking=stix2.TLP_AMBER, creator=AUTHOR)


def objects_of(bundle, stix_type):
    return [o for o in bundle["objects"] if o["type"] == stix_type]


# --------------------------------------------------------------------------
# extraction from the CIM fields
# --------------------------------------------------------------------------

@pytest.mark.parametrize("event, expected", [
    ({"url": "http://evil.test/a"}, ["url"]),
    ({"url_domain": "evil.test"}, ["domain-name"]),
    ({"dest_ip": "198.51.100.7"}, ["ipv4-addr"]),
    ({"src_ip": "2001:db8::1"}, ["ipv6-addr"]),
    ({"dest": "198.51.100.7"}, ["ipv4-addr"]),
    ({"src": "2001:db8::1"}, ["ipv6-addr"]),
    ({"file_hash": "d" * 32}, ["file"]),
    ({"file_name": "invoice.exe"}, ["file"]),
    ({"user": "jdoe"}, ["user-account"]),
    ({"user_name": "jdoe"}, ["user-account"]),
    ({"http_user_agent": "Mozilla/5.0"}, ["user-agent"]),
])
def test_cim_field_becomes_an_observable(event, expected):
    assert types_of(extract_cim(event)) == expected


def test_a_hostname_in_dest_is_kept():
    """A dest that is not an address is a hostname, it used to be dropped."""
    assert types_of(extract_cim({"dest": "WKS-001"})) == ["hostname"]


def test_a_hostname_in_src_is_kept():
    assert types_of(extract_cim({"src": "WKS-001"})) == ["hostname"]


@pytest.mark.parametrize("event", [
    {"url": ""},
    {"user": "unknown"},
    {"user_name": ""},
    {"dest_ip": ""},
    {},
])
def test_empty_or_unknown_values_are_skipped(event):
    assert extract_cim(event) == []


def test_a_full_event_yields_every_observable():
    event = {
        "url": "http://evil.test/a",
        "url_domain": "evil.test",
        "dest_ip": "198.51.100.7",
        "src_ip": "203.0.113.9",
        "file_hash": "f" * 64,
        "file_name": "invoice.exe",
        "user": "jdoe",
        "http_user_agent": "Mozilla/5.0",
    }
    assert len(extract_cim(event)) == 8


# --------------------------------------------------------------------------
# extraction from the octi_ prefixed fields
# --------------------------------------------------------------------------

@pytest.mark.parametrize("event, expected", [
    ({"octi_ip": "198.51.100.7"}, ["ipv4-addr"]),
    ({"octi_ip": "2001:db8::1"}, ["ipv6-addr"]),
    ({"octi_url": "http://evil.test/a"}, ["url"]),
    ({"octi_domain": "evil.test"}, ["domain-name"]),
    ({"octi_hash": "d" * 32}, ["file"]),
    ({"octi_hash": "f" * 64}, ["file"]),
    ({"octi_email_addr": "a@evil.test"}, ["email-addr"]),
    ({"octi_user_agent": "Mozilla/5.0"}, ["user-agent"]),
    ({"octi_mutex": "evil_mutex"}, ["mutex"]),
    ({"octi_text": "a note"}, ["text"]),
    ({"octi_directory": "/tmp/evil"}, ["directory"]),
    ({"octi_file_name": "invoice.exe"}, ["file"]),
    ({"octi_mac_addr": "00:11:22:33:44:55"}, ["mac-addr"]),
    ({"octi_user_account": "jdoe"}, ["user-account"]),
    ({"octi_windows_registry_key": "HKLM\\Run"}, ["windows-registry-key"]),
])
def test_octi_field_becomes_an_observable(event, expected):
    assert types_of(extract_fields(event)) == expected


def test_fields_without_the_prefix_are_ignored():
    assert extract_fields({"ip": "198.51.100.7", "url": "http://evil.test/"}) == []


def test_an_unrecognised_hash_is_skipped():
    assert extract_fields({"octi_hash": "not-a-hash"}) == []


# --------------------------------------------------------------------------
# incident
# --------------------------------------------------------------------------

@pytest.fixture
def incident_params():
    def build(**overrides):
        params = {
            "name": "Suspicious beaconing",
            "description": "Repeated calls to a known C2",
            "type": "alert",
            "severity": "high",
            "labels": ["c2", "beaconing"],
            "tlp": "tlp_amber",
            "observables_extraction": "cim_model",
        }
        params.update(overrides)
        return params

    return build


def test_incident_bundle_holds_the_incident(incident_params, alert_event):
    bundle = json.loads(convert_to_incident(incident_params(), alert_event))
    incident = objects_of(bundle, "incident")[0]
    assert incident["name"] == "Suspicious beaconing"
    assert incident["labels"] == ["c2", "beaconing"]


def test_incident_is_authored_by_the_splunk_host(incident_params, alert_event):
    bundle = json.loads(convert_to_incident(incident_params(), alert_event))
    author = objects_of(bundle, "identity")[0]
    incident = objects_of(bundle, "incident")[0]
    assert author["name"] == "splunk-search-01"
    assert incident["created_by_ref"] == author["id"]


def test_incident_links_the_extracted_observables(incident_params, alert_event):
    event = dict(alert_event, dest_ip="198.51.100.7", url="http://evil.test/a")
    bundle = json.loads(convert_to_incident(incident_params(), event))
    incident = objects_of(bundle, "incident")[0]
    relationships = objects_of(bundle, "relationship")
    assert len(relationships) == 2
    for relationship in relationships:
        assert relationship["relationship_type"] == "related-to"
        assert relationship["target_ref"] == incident["id"]


def test_incident_extraction_can_be_disabled(incident_params, alert_event):
    event = dict(alert_event, dest_ip="198.51.100.7")
    bundle = json.loads(convert_to_incident(
        incident_params(observables_extraction="disable"), event))
    assert objects_of(bundle, "relationship") == []
    assert objects_of(bundle, "ipv4-addr") == []


def test_incident_uses_the_field_mapping(incident_params, alert_event):
    event = dict(alert_event, octi_ip="198.51.100.7")
    bundle = json.loads(convert_to_incident(
        incident_params(observables_extraction="field_mapping"), event))
    assert objects_of(bundle, "ipv4-addr")


def test_incident_is_stable_for_the_same_alert(incident_params, alert_event):
    first = json.loads(convert_to_incident(incident_params(), alert_event))
    second = json.loads(convert_to_incident(incident_params(), alert_event))
    assert objects_of(first, "incident")[0]["id"] == objects_of(second, "incident")[0]["id"]


# --------------------------------------------------------------------------
# incident response case
# --------------------------------------------------------------------------

@pytest.fixture
def case_params():
    def build(**overrides):
        params = {
            "name": "Phishing campaign",
            "description": "Several users targeted",
            "severity": "medium",
            "priority": "p2",
            "labels": ["phishing"],
            "tlp": "tlp_green",
            "observables_extraction": "cim_model",
        }
        params.update(overrides)
        return params

    return build


def test_case_bundle_holds_the_case(case_params, alert_event):
    bundle = json.loads(convert_to_incident_response(case_params(), alert_event))
    case = objects_of(bundle, "case-incident")[0]
    assert case["name"] == "Phishing campaign"
    assert case["priority"] == "p2"
    assert case["labels"] == ["phishing"]


def test_case_references_the_observables(case_params, alert_event):
    event = dict(alert_event, dest_ip="198.51.100.7", file_name="invoice.exe")
    bundle = json.loads(convert_to_incident_response(case_params(), event))
    case = objects_of(bundle, "case-incident")[0]
    assert len(case["object_refs"]) == 2


def test_case_carries_the_marking(case_params, alert_event):
    bundle = json.loads(convert_to_incident_response(case_params(), alert_event))
    case = objects_of(bundle, "case-incident")[0]
    assert case["object_marking_refs"]


@pytest.mark.parametrize("tlp", ["tlp_clear", "tlp_green", "tlp_amber", "tlp_red"])
def test_every_tlp_is_accepted(case_params, alert_event, tlp):
    bundle = json.loads(convert_to_incident_response(case_params(tlp=tlp), alert_event))
    assert objects_of(bundle, "case-incident")[0]["object_marking_refs"]


def test_an_event_without_a_time_still_converts(case_params):
    bundle = json.loads(convert_to_incident_response(case_params(), {"host": "splunk"}))
    assert objects_of(bundle, "case-incident")
