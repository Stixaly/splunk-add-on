"""Unit tests for the refresh of a sighted indicator.

The OpenCTI API is replaced by a fake that records every GraphQL call, so the
tests check what the add-on asks OpenCTI for, not what OpenCTI does with it.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

import app_connector_helper
import modalert_opencti_create_sighting_helper as sighting_helper
from app_connector_helper import SplunkAppConnectorHelper
from stix_converter import convert_to_sighting
from utils import generate_indicator_id

UTC = timezone.utc
INDICATOR_ID = "indicator--3ae0b0a2-7289-5fda-8a85-02d057ba0968"
NOVEMBER_6TH = datetime(2025, 11, 6, 8, tzinfo=UTC)


class FakeSplunkHelper:
    def __init__(self, params=None):
        self.params = params or {}
        self.logs = {"info": [], "debug": [], "error": [], "warning": []}

    def get_param(self, name):
        return self.params.get(name)

    def get_global_setting(self, name):
        return {"opencti_url": "https://opencti.test", "opencti_api_key": "token"}.get(name)

    def _get_proxy_uri(self):
        return None

    def log_info(self, message):
        self.logs["info"].append(str(message))

    def log_debug(self, message):
        self.logs["debug"].append(str(message))

    def log_error(self, message):
        self.logs["error"].append(str(message))

    def log_warning(self, message):
        self.logs["warning"].append(str(message))


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.status_code = status_code
        self._payload = payload
        self.content = json.dumps(payload).encode("utf-8")

    def json(self):
        return self._payload


class FakeOpenCTI:
    """Answers the two GraphQL operations the refresh uses."""

    def __init__(self):
        self.calls = []
        self.indicator = None
        self.status_code = 200
        self.errors = None

    def post(self, url, json, headers, verify, proxies):
        assert url == "https://opencti.test/graphql"
        assert headers["Authorization"] == "Bearer token"
        if self.status_code != 200:
            return FakeResponse({}, self.status_code)
        if self.errors:
            return FakeResponse({"errors": self.errors})
        query, variables = json["query"], json["variables"]
        if "indicator(id:" in query:
            self.calls.append(("read", variables))
            return FakeResponse({"data": {"indicator": self.indicator}})
        if "indicatorFieldPatch" in query:
            self.calls.append(("patch", variables))
            for edit in variables["input"]:
                self.indicator[edit["key"]] = edit["value"][0]
            return FakeResponse({"data": {"indicatorFieldPatch": dict(self.indicator)}})
        raise AssertionError("unexpected query: " + query)


def existing_indicator(valid_until="2025-09-01T00:00:00.000Z", score=60):
    return {"id": "1f0d1b2c", "standard_id": INDICATOR_ID, "x_opencti_score": score,
            "valid_until": valid_until, "revoked": False}


@pytest.fixture
def opencti(monkeypatch):
    fake = FakeOpenCTI()
    monkeypatch.setattr(app_connector_helper.requests, "post", fake.post)
    return fake


@pytest.fixture
def connector():
    return SplunkAppConnectorHelper(
        connector_id="a6edc906", connector_name="Splunk App",
        opencti_url="https://opencti.test", opencti_api_key="token",
        splunk_helper=FakeSplunkHelper())


def patches(opencti):
    return [(call[1]["input"][0]["key"], call[1]["input"][0]["value"][0])
            for call in opencti.calls if call[0] == "patch"]


# --------------------------------------------------------------------------
# SplunkAppConnectorHelper.refresh_indicator
# --------------------------------------------------------------------------

def test_an_absent_indicator_is_left_to_the_bundle(opencti, connector):
    opencti.indicator = None
    assert connector.refresh_indicator(INDICATOR_ID, score=100, valid_until=NOVEMBER_6TH) is None
    assert [call[0] for call in opencti.calls] == ["read"]


def test_the_id_is_handed_to_opencti_as_given(opencti, connector):
    opencti.indicator = existing_indicator()
    connector.refresh_indicator(INDICATOR_ID, score=100)
    assert all(call[1]["id"] == INDICATOR_ID for call in opencti.calls)


def test_the_score_is_sent_on_its_own_before_the_validity(opencti, connector):
    """OpenCTI drops the score of an update that also carries valid_until."""
    opencti.indicator = existing_indicator()
    connector.refresh_indicator(INDICATOR_ID, score=100, valid_until=NOVEMBER_6TH)
    assert patches(opencti) == [("x_opencti_score", 100), ("valid_until", "2025-11-06T08:00:00Z")]
    assert all(len(call[1]["input"]) == 1 for call in opencti.calls if call[0] == "patch")


def test_only_the_score_is_sent_without_a_validity(opencti, connector):
    opencti.indicator = existing_indicator()
    connector.refresh_indicator(INDICATOR_ID, score=100)
    assert patches(opencti) == [("x_opencti_score", 100)]


def test_only_the_validity_is_sent_without_a_score(opencti, connector):
    opencti.indicator = existing_indicator()
    connector.refresh_indicator(INDICATOR_ID, valid_until=NOVEMBER_6TH)
    assert patches(opencti) == [("valid_until", "2025-11-06T08:00:00Z")]


def test_the_validity_is_kept_when_already_later(opencti, connector):
    """A sighting must never shorten the life of an indicator."""
    opencti.indicator = existing_indicator(valid_until="2026-01-01T00:00:00.000Z")
    connector.refresh_indicator(INDICATOR_ID, valid_until=NOVEMBER_6TH)
    assert patches(opencti) == []
    assert any("left unchanged" in line for line in connector.splunk_helper.logs["info"])


def test_a_missing_validity_is_set(opencti, connector):
    opencti.indicator = existing_indicator(valid_until=None)
    connector.refresh_indicator(INDICATOR_ID, valid_until=NOVEMBER_6TH)
    assert patches(opencti) == [("valid_until", "2025-11-06T08:00:00Z")]


def test_the_validity_compared_is_the_one_after_the_score_update(opencti, connector):
    """A score change makes OpenCTI recompute valid_until, the comparison has
    to use that new value and not the one read before."""
    opencti.indicator = existing_indicator(valid_until="2025-09-01T00:00:00.000Z")

    original_post = opencti.post

    def post(url, json, headers, verify, proxies):
        response = original_post(url, json, headers, verify, proxies)
        if "indicatorFieldPatch" in json["query"] and json["variables"]["input"][0]["key"] == "x_opencti_score":
            opencti.indicator["valid_until"] = "2026-06-01T00:00:00.000Z"
            response._payload["data"]["indicatorFieldPatch"]["valid_until"] = "2026-06-01T00:00:00.000Z"
        return response

    app_connector_helper.requests.post = post
    connector.refresh_indicator(INDICATOR_ID, score=100, valid_until=NOVEMBER_6TH)
    assert patches(opencti) == [("x_opencti_score", 100)]


def test_the_validity_is_sent_in_utc(opencti, connector):
    opencti.indicator = existing_indicator()
    paris = datetime(2025, 11, 6, 10, tzinfo=timezone(timedelta(hours=2)))
    connector.refresh_indicator(INDICATOR_ID, valid_until=paris)
    assert patches(opencti) == [("valid_until", "2025-11-06T08:00:00Z")]


def test_a_functional_error_is_raised(opencti, connector):
    """OpenCTI answers 200 with an errors list, which must not pass as success."""
    opencti.errors = [{"message": "Cannot edit the field, Indicator cannot be found."}]
    with pytest.raises(Exception, match="Indicator cannot be found"):
        connector.refresh_indicator(INDICATOR_ID, score=100)


def test_a_transport_error_is_raised(opencti, connector):
    opencti.status_code = 500
    with pytest.raises(Exception, match="status code: 500"):
        connector.refresh_indicator(INDICATOR_ID, score=100)


# --------------------------------------------------------------------------
# the alert helper around it
# --------------------------------------------------------------------------

class RecordingConnector:
    def __init__(self, failing=False):
        self.calls = []
        self.failing = failing

    def register(self):
        self.calls.append(("register",))

    def send_stix_bundle(self, bundle):
        if self.failing:
            raise Exception("queue is down")
        self.calls.append(("send", bundle))

    def refresh_indicator(self, indicator_id, score=None, valid_until=None):
        self.calls.append(("refresh", indicator_id, score, valid_until))


def sighting_bundle(sighting_params, alert_event, **overrides):
    return convert_to_sighting(sighting_params(**overrides), alert_event)


def test_no_parameter_means_no_refresh(sighting_params, alert_event):
    helper, connector = FakeSplunkHelper(), RecordingConnector()
    params = sighting_params()
    sighting_helper.refresh_sighted_indicator(
        helper, connector, sighting_bundle(sighting_params, alert_event), params)
    assert connector.calls == []


def test_the_refresh_targets_the_sighted_indicator(sighting_params, alert_event):
    helper, connector = FakeSplunkHelper(), RecordingConnector()
    params = sighting_params(last_seen="1754640000", indicator_score="100",
                             indicator_validity_days="90")
    sighting_helper.refresh_sighted_indicator(
        helper, connector, sighting_bundle(sighting_params, alert_event, **params), params)
    assert connector.calls == [
        ("refresh", generate_indicator_id("[ipv4-addr:value = '198.51.100.7']"), 100, NOVEMBER_6TH)]


def test_a_referenced_indicator_is_refreshed_by_its_id(sighting_params, alert_event):
    helper, connector = FakeSplunkHelper(), RecordingConnector()
    params = sighting_params(sighting_of_type="indicator", sighting_of_value=INDICATOR_ID,
                             indicator_score="100")
    sighting_helper.refresh_sighted_indicator(
        helper, connector, sighting_bundle(sighting_params, alert_event, **params), params)
    assert connector.calls == [("refresh", INDICATOR_ID, 100, None)]


def test_an_observable_sighting_is_not_refreshed(sighting_params, alert_event):
    helper, connector = FakeSplunkHelper(), RecordingConnector()
    params = sighting_params(sighting_of_type="ipv4_observable", indicator_score="100",
                             indicator_validity_days="90")
    sighting_helper.refresh_sighted_indicator(
        helper, connector, sighting_bundle(sighting_params, alert_event, **params), params)
    assert connector.calls == []
    assert any("observable" in line for line in helper.logs["info"])


def test_a_failing_refresh_is_logged_and_does_not_raise(sighting_params, alert_event):
    class Failing(RecordingConnector):
        def refresh_indicator(self, indicator_id, score=None, valid_until=None):
            raise Exception("OpenCTI returned an error: boom")

    helper = FakeSplunkHelper()
    params = sighting_params(indicator_score="100")
    sighting_helper.refresh_sighted_indicator(
        helper, Failing(), sighting_bundle(sighting_params, alert_event, **params), params)
    assert len(helper.logs["error"]) == 1
    assert "boom" in helper.logs["error"][0]


def test_create_sighting_sends_the_bundle_then_refreshes(monkeypatch, alert_event):
    connector = RecordingConnector()
    monkeypatch.setattr(sighting_helper, "SplunkAppConnectorHelper", lambda **kwargs: connector)
    helper = FakeSplunkHelper({
        "sighting_of_value": INDICATOR_ID, "sighting_of_type": "indicator",
        "where_sighted_value": "Splunk - main", "where_sighted_type": "system",
        "count": "12", "first_seen": "1754600000", "last_seen": "1754640000",
        "indicator_score": "100", "indicator_validity_days": "90",
        "labels": "alpha, beta", "tlp": "tlp_amber",
    })
    sighting_helper.create_sighting(helper, alert_event)

    assert [call[0] for call in connector.calls] == ["register", "send", "refresh"]
    assert connector.calls[2] == ("refresh", INDICATOR_ID, 100, NOVEMBER_6TH)
    sighting = [o for o in json.loads(connector.calls[1][1])["objects"] if o["type"] == "sighting"][0]
    assert sighting["count"] == 12
    assert helper.logs["error"] == []


def test_create_sighting_does_not_refresh_when_the_bundle_fails(monkeypatch, alert_event):
    connector = RecordingConnector(failing=True)
    monkeypatch.setattr(sighting_helper, "SplunkAppConnectorHelper", lambda **kwargs: connector)
    helper = FakeSplunkHelper({
        "sighting_of_value": INDICATOR_ID, "sighting_of_type": "indicator",
        "where_sighted_value": "Splunk", "where_sighted_type": "system",
        "indicator_score": "100", "tlp": "tlp_amber",
    })
    sighting_helper.create_sighting(helper, alert_event)

    assert [call[0] for call in connector.calls] == ["register"]
    assert len(helper.logs["error"]) == 1
