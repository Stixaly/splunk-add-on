"""Checks the packaged configuration against the code.

The .conf and .html files are read by Splunk, not by the tests, so a mistake in
them is invisible until the add-on is deployed. These tests keep them parseable,
consistent with the Python side, and in the encoding Splunk was given.
"""
import configparser
import re

import pytest

from conftest import ADDON, DEFAULT

COLLECTIONS = DEFAULT / "collections.conf"
TRANSFORMS = DEFAULT / "transforms.conf"
ALERT_ACTIONS = DEFAULT / "alert_actions.conf"
SIGHTING_FORM = DEFAULT / "data" / "ui" / "alerts" / "opencti_create_sighting.html"
ALERT_ACTIONS_SPEC = ADDON / "README" / "alert_actions.conf.spec"

SINGLE_COLLECTION = "opencti_indicators"
COMPOSITE_COLLECTION = "opencti_indicators_composite"

# Fields holding a list of values. A scalar type on them makes the KV store
# coerce the list and keep a single value, which is the bug this guards.
MULTI_VALUED = ["labels", "markings", "indicator_types"]


def read_conf(path):
    parser = configparser.ConfigParser(strict=False)
    parser.read(path, encoding="utf-8-sig")
    return parser


def fields_list(section):
    raw = read_conf(TRANSFORMS).get(section, "fields_list")
    return [field.strip() for field in raw.split(",")]


# --------------------------------------------------------------------------
# the files stay readable by Splunk
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path", [COLLECTIONS, TRANSFORMS, ALERT_ACTIONS])
def test_conf_file_parses(path):
    assert read_conf(path).sections()


def test_collections_conf_keeps_its_byte_order_mark():
    """Splunk was shipped this file with a BOM, an edit must not drop it."""
    assert COLLECTIONS.read_bytes().startswith(b"\xef\xbb\xbf")


@pytest.mark.parametrize("path", [COLLECTIONS, TRANSFORMS, ALERT_ACTIONS, SIGHTING_FORM])
def test_line_endings_are_not_mixed(path):
    """Which style a file uses depends on how git checked it out, but a file
    mixing two of them is the sign of an edit made without care for the rest."""
    data = path.read_bytes()
    crlf = data.count(b"\r\n")
    styles = {
        "CRLF": crlf,
        "CR": data.count(b"\r") - crlf,
        "LF": data.count(b"\n") - crlf,
    }
    used = sorted(style for style, count in styles.items() if count)
    assert len(used) == 1, "%s mixes line endings: %s" % (path.name, used)


# --------------------------------------------------------------------------
# single value collection
# --------------------------------------------------------------------------

def test_single_collection_exists():
    assert SINGLE_COLLECTION in read_conf(COLLECTIONS).sections()


@pytest.mark.parametrize("field", MULTI_VALUED)
def test_multi_valued_field_has_no_scalar_type(field):
    """field.<name> = string on a list makes the KV store keep one value."""
    declared = read_conf(COLLECTIONS).options(SINGLE_COLLECTION)
    assert "field.%s" % field not in declared


@pytest.mark.parametrize("field", MULTI_VALUED)
def test_multi_valued_field_is_still_exposed_by_the_lookup(field):
    assert field in fields_list("opencti_lookup")


def test_single_lookup_points_at_the_single_collection():
    assert read_conf(TRANSFORMS).get("opencti_lookup", "collection") == SINGLE_COLLECTION


def test_every_field_written_by_the_input_is_exposed(input_module, helper,
                                                     stream_indicator, markings):
    """A column the input writes but the lookup hides is invisible in SPL."""
    record = markings.enrich_payload(helper, stream_indicator)
    record["added_at"] = "2026-01-01T00:00:00Z"
    exposed = set(fields_list("opencti_lookup"))
    expected = {"_key", "id", "name", "pattern", "type", "value", "labels", "markings",
                "indicator_types", "created_by", "score", "detection", "valid_from",
                "added_at", "input_name", "stream_id"}
    missing = sorted(expected - exposed)
    assert not missing, "not exposed by opencti_lookup: %s" % missing
    assert expected <= set(record), "the input no longer writes some of those fields"


# --------------------------------------------------------------------------
# composite collection
# --------------------------------------------------------------------------

def test_composite_collection_exists():
    assert COMPOSITE_COLLECTION in read_conf(COLLECTIONS).sections()


def test_composite_lookup_points_at_the_composite_collection():
    assert read_conf(TRANSFORMS).get(
        "opencti_composite_lookup", "collection") == COMPOSITE_COLLECTION


def test_every_cim_column_is_declared():
    """A CIM field the parser can emit must exist in the collection."""
    from stix_pattern import CIM_FIELDS

    declared = {option[len("field."):]
                for option in read_conf(COLLECTIONS).options(COMPOSITE_COLLECTION)
                if option.startswith("field.")}
    missing = sorted(set(CIM_FIELDS.values()) - declared)
    assert not missing, "missing from collections.conf: %s" % missing


def test_every_cim_column_is_exposed():
    from stix_pattern import CIM_FIELDS

    missing = sorted(set(CIM_FIELDS.values()) - set(fields_list("opencti_composite_lookup")))
    assert not missing, "missing from the composite fields_list: %s" % missing


def test_composite_collection_records_the_indicator_and_the_match_fields():
    declared = read_conf(COLLECTIONS).options(COMPOSITE_COLLECTION)
    assert "field.indicator_id" in declared
    assert "field.match_fields" in declared


def test_collection_names_agree_with_the_code():
    import stix_pattern

    assert stix_pattern.SINGLE_COLLECTION == SINGLE_COLLECTION
    assert stix_pattern.COMPOSITE_COLLECTION == COMPOSITE_COLLECTION


# --------------------------------------------------------------------------
# the sighting alert action
# --------------------------------------------------------------------------

def sighting_form_options():
    html = SIGHTING_FORM.read_bytes().decode("utf-8")
    block = html.split('id="opencti_create_sighting_sighting_of_type"')[1].split("</select>")[0]
    return re.findall(r'<option value="([^"]+)"', block)


def test_the_form_offers_the_indicator_types():
    from stix_converter import STIX_PATTERNS

    options = sighting_form_options()
    assert "indicator" in options
    for observable_type in STIX_PATTERNS:
        assert observable_type + "_indicator" in options, \
            "%s can be built but cannot be selected" % observable_type


def test_the_form_still_offers_the_observable_types():
    options = sighting_form_options()
    for legacy in ["url_observable", "domain_observable", "ipv4_observable", "ipv6_observable"]:
        assert legacy in options, "an existing alert would stop working"


def test_the_default_type_is_a_valid_option():
    default = read_conf(ALERT_ACTIONS).get("opencti_create_sighting", "param.sighting_of_type")
    assert default.strip() in sighting_form_options()


def test_every_form_option_is_accepted_by_the_converter(sighting_params, alert_event):
    """No option may lead to the "Invalid sighting_of_type" failure."""
    import json

    from stix_converter import convert_to_sighting

    values = {"indicator": "indicator--3ae0b0a2-7289-5fda-8a85-02d057ba0968"}
    defaults = {"ipv4": "198.51.100.7", "ipv6": "2001:db8::1", "url": "http://evil.test/a",
                "domain": "evil.test", "hostname": "WKS-001", "email_addr": "a@evil.test",
                "user_agent": "Mozilla/5.0", "file_name": "invoice.exe",
                "md5": "d" * 32, "sha1": "e" * 40, "sha256": "f" * 64, "sha512": "a" * 128}

    for option in sighting_form_options():
        value = values.get(option) or defaults.get(option.rsplit("_", 1)[0], "198.51.100.7")
        bundle = json.loads(convert_to_sighting(
            sighting_params(sighting_of_type=option, sighting_of_value=value), alert_event))
        sightings = [o for o in bundle["objects"] if o["type"] == "sighting"]
        assert len(sightings) == 1, "%s produced no sighting" % option


def sighting_params_of(path):
    options = read_conf(path).options("opencti_create_sighting")
    return {option[len("param."):] for option in options if option.startswith("param.")}


def sighting_form_params():
    html = SIGHTING_FORM.read_bytes().decode("utf-8")
    return set(re.findall(r'name="action\.opencti_create_sighting\.param\.([a-z_]+)"', html))


def test_every_sighting_parameter_is_declared_everywhere():
    """A parameter in the form but not in alert_actions.conf is not saved by
    Splunk, one in the conf but not in the spec fails the app inspection, and
    one declared but absent from the form cannot be filled in."""
    assert sighting_form_params() == sighting_params_of(ALERT_ACTIONS)
    assert sighting_params_of(ALERT_ACTIONS) == sighting_params_of(ALERT_ACTIONS_SPEC)


# parameters that are empty unless the alert asks for more than a plain sighting
OPTIONAL_SIGHTING_PARAMS = [
    "count", "first_seen", "last_seen", "indicator_score", "indicator_validity_days",
]


@pytest.mark.parametrize("param", OPTIONAL_SIGHTING_PARAMS)
def test_the_optional_sighting_parameters_are_offered(param):
    assert param in sighting_form_params()


@pytest.mark.parametrize("param", OPTIONAL_SIGHTING_PARAMS)
def test_the_optional_sighting_parameters_have_no_default(param):
    """An empty value is what makes the converter fall back to a single event
    with a count of one and leave the indicator alone, so an existing alert
    keeps its behaviour."""
    assert read_conf(ALERT_ACTIONS).get("opencti_create_sighting", "param." + param).strip() == ""


def test_the_labels_field_defaults_to_the_lookup_field():
    """The labels of a matched indicator reach the sighting without any token
    because the default names the field opencti_lookup returns."""
    default = read_conf(ALERT_ACTIONS).get("opencti_create_sighting", "param.labels_field")
    assert default.strip() == "labels"
    assert "labels" in fields_list("opencti_lookup")
