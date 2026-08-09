"""One test per defect that has been fixed, so none of them can come back.

Each test names the behaviour that was wrong and asserts the corrected one.
"""
import json
import os
import time
from datetime import datetime, timedelta, timezone

import pytest
import stix2

import stix_converter
from stix_converter import FAKE_INDICATOR_ID, convert_to_sighting

AUTHOR = stix2.Identity(
    id="identity--11111111-1111-4111-8111-111111111111",
    name="test", identity_class="system")


def convert(observable_type, value):
    return stix_converter._convert_observables_to_stix(
        observables=[{"type": observable_type, "value": value}],
        marking=stix2.TLP_AMBER, creator=AUTHOR)


# --------------------------------------------------------------------------
# ingestion
# --------------------------------------------------------------------------

def test_markings_are_not_reset_by_the_loop(markings, helper, stream_indicator):
    """The accumulator used to be emptied inside the loop, so only the last
    marking of an indicator survived."""
    record = markings.enrich_payload(helper, stream_indicator)
    assert record["markings"] == ["TLP:GREEN", "PAP:AMBER"], \
        "a marking was lost, the accumulator is being reset again"


def test_labels_reach_the_kv_store_as_a_list(markings, helper, stream_indicator):
    """The value handed to batch_save has to stay a JSON array. A string would
    be a single value once in the KV store."""
    stream_indicator["labels"] = ["c2", "cobalt-strike", "apt29"]
    record = markings.enrich_payload(helper, stream_indicator)
    on_the_wire = json.loads(json.dumps([record]))[0]
    assert isinstance(on_the_wire["labels"], list)
    assert len(on_the_wire["labels"]) == 3


@pytest.mark.parametrize("pattern, expected", [
    (r"[windows-registry-key:key = 'HKLM\\Software\\Evil']", r"HKLM\Software\Evil"),
    (r"[directory:path = 'C:\\Temp\\evil']", r"C:\Temp\evil"),
    (r"[mutex:name = 'Global\\evil']", r"Global\evil"),
    (r"[file:name = 'O\'Brien.doc']", "O'Brien.doc"),
])
def test_stix_escaping_is_removed(input_module, pattern, expected):
    """Values used to keep their STIX escaping, so a registry key or a path
    reached the KV store with doubled backslashes and matched nothing."""
    assert input_module.parse_stix_pattern(pattern)["value"] == expected


def test_a_list_index_in_the_path_does_not_crash(input_module):
    """protocols[*] and values[*] carry a non string element in the path, and
    joining it raised a TypeError that skipped the whole indicator."""
    assert input_module.parse_stix_pattern("[windows-registry-key:values[*].name = 'Run']") is None


def test_email_message_is_matched_on_its_subject(input_module):
    """email-message was declared with a "value" attribute, which OpenCTI never
    emits, so the type looked supported but could never match."""
    parsed = input_module.parse_stix_pattern("[email-message:subject = 'invoice']")
    assert parsed == {"type": "email-message", "value": "invoice"}


def test_sha512_is_ingested(input_module):
    """SHA-512 could be sighted but not ingested."""
    parsed = input_module.parse_stix_pattern("[file:hashes.'SHA-512' = '%s']" % ("a" * 128))
    assert parsed["type"] == "sha512"


def test_non_stix_indicators_are_reported(input_module, helper):
    """A yara or sigma indicator used to be dropped without a single log line."""
    assert "pattern_type" in _collect_events_source(input_module)


def _collect_events_source(module):
    import inspect
    return inspect.getsource(module.collect_events)


def test_the_skipped_indicator_log_mentions_the_pattern_type(input_module):
    source = _collect_events_source(input_module)
    assert "only stix patterns are ingested" in source


def test_message_failures_are_logged_as_errors(input_module):
    """A failure while processing a message was only logged at debug level."""
    source = _collect_events_source(input_module)
    assert "log_error(f\"Error when processing message" in source


# --------------------------------------------------------------------------
# observable conversion
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# dates
# --------------------------------------------------------------------------

@pytest.fixture
def server_timezone():
    """Runs a test as if the Splunk server sat in a given timezone."""
    if not hasattr(time, "tzset"):
        pytest.skip("changing the timezone at runtime needs a POSIX platform")

    previous = os.environ.get("TZ")

    def apply(name):
        os.environ["TZ"] = name
        time.tzset()

    yield apply

    if previous is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = previous
    time.tzset()


@pytest.mark.parametrize("timezone_name", [
    "Europe/Paris", "America/New_York", "Asia/Tokyo", "Australia/Sydney",
])
def test_the_first_collection_starts_at_the_same_instant_everywhere(
        server_timezone, run_first_collection, timezone_name):
    """The start of the first collection was built from a naive datetime, and
    timestamp() reads those as local time. The window therefore moved with the
    timezone of the Splunk server, and indicators were missed west of UTC.

    The input is run twice, once in UTC and once elsewhere, and has to ask the
    stream for the same position both times.
    """
    server_timezone("UTC")
    in_utc = int(run_first_collection()["start_from"].split("-")[0])

    server_timezone(timezone_name)
    elsewhere = int(run_first_collection()["start_from"].split("-")[0])

    drift_hours = abs(in_utc - elsewhere) / 3600000.0
    assert drift_hours < 0.1, (
        "the collection starts %.0f h apart in UTC and in %s"
        % (drift_hours, timezone_name))


def test_the_input_builds_its_dates_with_a_timezone(input_module):
    """A naive utcnow() is both deprecated and wrong once given to
    timestamp(), it must not come back."""
    import inspect

    source = inspect.getsource(input_module)
    assert "utcnow()" not in source, "utcnow() is deprecated, use now(timezone.utc)"


def test_date_now_z_is_an_utc_iso_string(input_module):
    value = input_module.date_now_z()
    assert value.endswith("Z")
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert abs((datetime.now(timezone.utc) - parsed).total_seconds()) < 60


def test_the_checkpoint_start_is_a_millisecond_epoch(run_first_collection):
    """The stream expects <epoch millis>-<sequence>."""
    state = run_first_collection()
    offset, _, sequence = state["start_from"].partition("-")
    assert sequence == "0"
    expected = (datetime.now(timezone.utc) - timedelta(days=30)).timestamp() * 1000
    assert abs(int(offset) - expected) < 60000


def test_hostname_observable_is_not_dropped():
    """There was no hostname branch, so a src or dest that is not an address
    was silently lost by the CIM extraction."""
    converted = convert("hostname", "WKS-001")
    assert len(converted) == 1
    assert converted[0].type == "hostname"


def test_mac_address_observable_builds():
    """MACAddress was given a subject property, which raised
    ExtraPropertiesError and failed the whole alert action."""
    converted = convert("mac_addr", "00:11:22:33:44:55")
    assert converted[0].type == "mac-addr"
    assert converted[0].value == "00:11:22:33:44:55"


@pytest.mark.parametrize("value, stix_type", [
    ("d" * 32, "file"),
    ("f" * 64, "file"),
])
def test_a_cim_file_hash_is_not_dropped(value, stix_type):
    """The CIM extraction produced {"type": "hash"}, a type the converter has
    no branch for, so the hash of an alert never reached OpenCTI."""
    observables = stix_converter._extract_observables_from_cim_model(
        event={"file_hash": value}, marking=stix2.TLP_AMBER, creator=AUTHOR)
    assert len(observables) == 1
    assert observables[0].type == stix_type


def test_email_message_observable_builds():
    """EmailMessage requires is_multipart, without it the alert action failed
    with MissingPropertiesError."""
    converted = convert("email_message", "invoice")
    assert converted[0].type == "email-message"
    assert converted[0].is_multipart is False


# --------------------------------------------------------------------------
# sightings
# --------------------------------------------------------------------------

def test_an_unknown_sighting_type_is_an_error(sighting_params, alert_event):
    """A type that matched no branch produced a bundle without any sighting and
    reported success."""
    with pytest.raises(Exception, match="Invalid sighting_of_type"):
        convert_to_sighting(sighting_params(sighting_of_type="banana"), alert_event)


def test_an_unsupported_observable_is_an_error(sighting_params, alert_event):
    """The first element of an empty list used to raise an IndexError."""
    with pytest.raises(Exception, match="Unsupported sighting_of_type"):
        convert_to_sighting(
            sighting_params(sighting_of_type="banana_observable", sighting_of_value="x"),
            alert_event)


def test_a_sighting_can_target_an_indicator(sighting_params, alert_event):
    """Every sighting used to be attached to an observable through the
    placeholder indicator."""
    bundle = json.loads(convert_to_sighting(
        sighting_params(sighting_of_type="ipv4_indicator", sighting_of_value="198.51.100.7"),
        alert_event))
    sighting = [o for o in bundle["objects"] if o["type"] == "sighting"][0]
    assert sighting["sighting_of_ref"] != FAKE_INDICATOR_ID
    assert sighting["sighting_of_ref"].startswith("indicator--")


def test_the_observable_sighting_still_uses_the_placeholder(sighting_params, alert_event):
    """The behaviour of the earlier versions must not change for the alerts
    that already use it."""
    bundle = json.loads(convert_to_sighting(
        sighting_params(sighting_of_type="ipv4_observable", sighting_of_value="198.51.100.7"),
        alert_event))
    sighting = [o for o in bundle["objects"] if o["type"] == "sighting"][0]
    assert sighting["sighting_of_ref"] == FAKE_INDICATOR_ID


def test_the_sighting_alert_validates_its_parameters():
    """validate_params was a commented out stub that accepted anything."""
    import inspect
    from pathlib import Path

    from conftest import BIN

    source = Path(BIN / "opencti_create_sighting.py").read_text(encoding="utf-8")
    body = source.split("def validate_params")[1].split("def ")[0]
    assert "sighting_of_value" in body and "return False" in body
