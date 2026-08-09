"""Shared setup for the add-on test suite.

The add-on ships its dependencies in bin/ta_opencti_add_on/aob_py3 and its
modules import each other by bare name, the way Splunk runs them. The same
paths are put in front of sys.path here so a test imports exactly what Splunk
would, without a Splunk instance being needed.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADDON = ROOT / "TA-opencti-add-on"
BIN = ADDON / "bin"
PACKAGE = BIN / "ta_opencti_add_on"
VENDORED = PACKAGE / "aob_py3"
DEFAULT = ADDON / "default"

for _path in (VENDORED, PACKAGE, BIN):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


class FakeHelper:
    """Stands in for the Splunk modular input helper."""

    def __init__(self, stream_id="live-stream-1", input_name="opencti_indicators://test"):
        self._stream_id = stream_id
        self._input_name = input_name
        self.logs = {"info": [], "debug": [], "error": [], "warning": []}

    def get_arg(self, name):
        return self._stream_id if name == "stream_id" else None

    def get_input_stanza_names(self):
        return self._input_name

    def log_info(self, message):
        self.logs["info"].append(str(message))

    def log_debug(self, message):
        self.logs["debug"].append(str(message))

    def log_error(self, message):
        self.logs["error"].append(str(message))

    def log_warning(self, message):
        self.logs["warning"].append(str(message))


@pytest.fixture
def helper():
    return FakeHelper()


@pytest.fixture
def input_module():
    """The indicators modular input, with its caches emptied for each test."""
    import input_module_opencti_indicators as module

    module.MARKING_DEFs.clear()
    module.IDENTITY_DEFs.clear()
    yield module
    module.MARKING_DEFs.clear()
    module.IDENTITY_DEFs.clear()


@pytest.fixture
def stream_indicator():
    """An indicator shaped the way an OpenCTI live stream emits one.

    A copy is returned every time so a test can mutate it freely.
    """
    payload = {
        "id": "indicator--7c1e4a90-3f2b-4d55-8a1e-9b0c2d3e4f5a",
        "spec_version": "2.1",
        "type": "indicator",
        "created": "2026-07-01T10:00:00.000Z",
        "modified": "2026-07-14T08:12:31.000Z",
        "revoked": False,
        "confidence": 75,
        "lang": "en",
        "created_by_ref": "identity--b7a1f8c2-1111-4c3a-9f11-2c3d4e5f6a7b",
        "object_marking_refs": [
            "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "marking-definition--a1b2c3d4-0000-4000-8000-000000000001",
        ],
        "name": "Cobalt Strike C2",
        "description": "Observed beaconing to this host",
        "indicator_types": ["malicious-activity", "attribution"],
        "pattern": "[ipv4-addr:value = '198.51.100.7']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": "2026-07-01T10:00:00.000Z",
        "valid_until": "2026-10-01T10:00:00.000Z",
        "labels": ["c2", "cobalt-strike"],
        "external_references": [{"source_name": "ACME", "url": "https://acme.test/r/1"}],
        "extensions": {
            "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b": {
                "extension_type": "property-extension",
                "id": "7c1e4a90-3f2b-4d55-8a1e-9b0c2d3e4f5a",
                "type": "Indicator",
                "created_at": "2026-07-01T10:00:00.000Z",
                "updated_at": "2026-07-14T08:12:31.000Z",
                "is_inferred": False,
                "detection": True,
                "score": 80,
                "main_observable_type": "IPv4-Addr",
            }
        },
    }
    return json.loads(json.dumps(payload))


@pytest.fixture
def markings(input_module):
    """Marking definitions already seen on the stream."""
    input_module.MARKING_DEFs.update({
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:GREEN",
        "marking-definition--a1b2c3d4-0000-4000-8000-000000000001": "PAP:AMBER",
    })
    input_module.IDENTITY_DEFs.update({
        "identity--b7a1f8c2-1111-4c3a-9f11-2c3d4e5f6a7b": "ACME CTI",
    })
    return input_module


@pytest.fixture
def run_first_collection(input_module, monkeypatch):
    """Runs a collection that has no checkpoint yet, and reports where it starts.

    The position asked of the OpenCTI stream is the second argument given to
    SSEClient, so recording that call is the most direct way to see the window
    the input computed.
    """

    class _Helper(FakeHelper):
        log_level = "INFO"
        context_meta = {"session_key": "session"}

        def get_arg(self, name):
            return {"stream_id": "live-1", "import_from": "30"}.get(name)

        def get_global_setting(self, name):
            return {"opencti_url": "https://opencti.test",
                    "opencti_api_key": "token"}.get(name)

        def set_log_level(self, level):
            pass

        def _get_proxy_uri(self):
            return None

        def get_check_point(self, name):
            return None

        def save_check_point(self, name, state):
            pass

    def run():
        recorded = {}

        class _Splunk:
            kvstore = {"opencti_indicators": type("C", (), {"data": None})()}

        def fake_sse_client(url, start_from, **kwargs):
            recorded["url"] = url
            recorded["start_from"] = start_from
            return []

        monkeypatch.setattr(input_module.client, "connect", lambda **kwargs: _Splunk())
        monkeypatch.setattr(input_module, "SSEClient", fake_sse_client)

        input_module.collect_events(_Helper(), None)
        return recorded

    return run


@pytest.fixture
def alert_event():
    """A Splunk alert result handed to the alert actions."""
    return {"host": "splunk-search-01", "_time": "1754640000"}


@pytest.fixture
def sighting_params():
    def build(**overrides):
        params = {
            "sighting_of_value": "198.51.100.7",
            "sighting_of_type": "ipv4_indicator",
            "where_sighted_value": "Splunk",
            "where_sighted_type": "system",
            "labels": ["alpha", "beta"],
            "tlp": "tlp_amber",
        }
        params.update(overrides)
        return params

    return build
