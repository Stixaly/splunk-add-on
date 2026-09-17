"""Unit tests for the calls the add-on makes to the OpenCTI API.

requests.post is replaced by a fake, so the tests check what is sent and how
each kind of answer is read, without a platform.
"""
import json

import pytest

import app_connector_helper
from app_connector_helper import SplunkAppConnectorHelper


class FakeSplunkHelper:
    def __init__(self):
        self.logs = {"info": [], "debug": [], "error": [], "warning": []}

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
    def __init__(self, payload=None, status_code=200, body=None):
        self.status_code = status_code
        self._payload = payload
        self.content = body if body is not None else json.dumps(payload).encode("utf-8")

    def json(self):
        if self._payload is None:
            raise ValueError("not JSON")
        return self._payload


@pytest.fixture
def post(monkeypatch):
    """Records the request and answers what the test decided."""
    calls = []
    answers = []

    def fake_post(url, json, headers, verify, proxies):
        calls.append({"url": url, "json": json, "headers": headers, "verify": verify, "proxies": proxies})
        return answers.pop(0)

    monkeypatch.setattr(app_connector_helper.requests, "post", fake_post)
    fake_post.calls = calls
    fake_post.answers = answers
    return fake_post


@pytest.fixture
def connector():
    return SplunkAppConnectorHelper(
        connector_id="a6edc906-2f9f-5fb2-a373-efac406f0ef2", connector_name="Splunk App",
        opencti_url="https://opencti.test", opencti_api_key="token",
        splunk_helper=FakeSplunkHelper())


# --------------------------------------------------------------------------
# the request itself
# --------------------------------------------------------------------------

def test_the_request_goes_to_the_graphql_endpoint_with_the_token(post, connector):
    post.answers.append(FakeResponse({"data": {"stixBundlePush": True}}))
    connector.send_stix_bundle("{}")
    call = post.calls[0]
    assert call["url"] == "https://opencti.test/graphql"
    assert call["headers"] == {"Authorization": "Bearer token"}
    assert call["verify"] is True


def test_the_bundle_is_sent_with_the_connector_id(post, connector):
    post.answers.append(FakeResponse({"data": {"stixBundlePush": True}}))
    connector.send_stix_bundle('{"type": "bundle"}')
    variables = post.calls[0]["json"]["variables"]
    assert variables == {"id": "a6edc906-2f9f-5fb2-a373-efac406f0ef2", "bundle": '{"type": "bundle"}'}
    assert "stixBundlePush" in post.calls[0]["json"]["query"]


def test_registration_sends_the_connector_identity(post, connector):
    post.answers.append(FakeResponse({"data": {"registerConnector": {"id": "a6edc906"}}}))
    assert connector.register() == {"id": "a6edc906"}
    given = post.calls[0]["json"]["variables"]["input"]
    assert given["id"] == "a6edc906-2f9f-5fb2-a373-efac406f0ef2"
    assert given["name"] == "Splunk App"
    assert given["type"] == "STREAM"


# --------------------------------------------------------------------------
# how the answers are read
# --------------------------------------------------------------------------

@pytest.mark.parametrize("operation", ["register", "send_stix_bundle"])
def test_a_transport_error_is_raised(post, connector, operation):
    post.answers.append(FakeResponse({}, status_code=502))
    with pytest.raises(Exception, match="status code: 502"):
        getattr(connector, operation)(*(["{}"] if operation == "send_stix_bundle" else []))


@pytest.mark.parametrize("operation", ["register", "send_stix_bundle"])
def test_a_graphql_error_is_raised(post, connector, operation):
    """OpenCTI answers a functional error with a 200 status and an errors list."""
    post.answers.append(FakeResponse({
        "errors": [{"message": "You are not allowed to do this.", "name": "FORBIDDEN_ACCESS"}],
        "data": None,
    }))
    with pytest.raises(Exception, match="You are not allowed to do this"):
        getattr(connector, operation)(*(["{}"] if operation == "send_stix_bundle" else []))


def test_every_graphql_error_is_reported(post, connector):
    post.answers.append(FakeResponse({"errors": [{"message": "first"}, {"message": "second"}]}))
    with pytest.raises(Exception, match="first; second"):
        connector.register()


def test_a_refused_bundle_is_raised(post, connector):
    post.answers.append(FakeResponse({"data": {"stixBundlePush": False}}))
    with pytest.raises(Exception, match="did not accept"):
        connector.send_stix_bundle("{}")


def test_an_answer_that_is_not_json_is_raised(post, connector):
    """A proxy or a login page answers 200 with HTML."""
    post.answers.append(FakeResponse(body=b"<html>Sign in</html>"))
    with pytest.raises(Exception, match="not JSON"):
        connector.send_stix_bundle("{}")


def test_an_answer_that_is_not_an_object_is_raised(post, connector):
    post.answers.append(FakeResponse(payload=["unexpected"]))
    with pytest.raises(Exception, match="not a GraphQL response"):
        connector.send_stix_bundle("{}")


def test_a_successful_push_raises_nothing(post, connector):
    post.answers.append(FakeResponse({"data": {"stixBundlePush": True}}))
    connector.send_stix_bundle("{}")
    assert connector.splunk_helper.logs["error"] == []
