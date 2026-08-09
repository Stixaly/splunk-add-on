"""Unit tests for the stream consumption loop.

collect_events talks to Splunk and to the OpenCTI stream, so both are replaced
here: the KV store records what it is asked to write, and the stream is a plain
list of messages. Nothing else is stubbed, the module runs its real logic.
"""
import json

import pytest


class FakeKVStore:
    """Records what the input writes, the way the Splunk KV store would."""

    def __init__(self):
        self.saved = []
        self.deleted = []
        self.rows = {}
        self.fail_on_save = False

    def batch_save(self, *documents):
        if self.fail_on_save:
            raise Exception("kv store refused the record")
        for document in documents:
            self.saved.append(document)
            self.rows[document.get("_key")] = document

    def query_by_id(self, key):
        if key not in self.rows:
            raise Exception("not found")
        return self.rows[key]

    def delete_by_id(self, key):
        self.deleted.append(key)
        self.rows.pop(key, None)


class FakeMessage:
    def __init__(self, event, data, identifier):
        self.event = event
        self.data = json.dumps({"data": data})
        self.id = identifier


class StreamHelper:
    """The modular input helper, with everything collect_events touches."""

    log_level = "INFO"

    def __init__(self, checkpoint=None):
        self.context_meta = {"session_key": "session"}
        self.checkpoints = {"opencti_indicators://test": checkpoint}
        self.saved_checkpoints = []
        self.logs = {"info": [], "debug": [], "error": []}

    def set_log_level(self, level):
        pass

    def get_input_stanza_names(self):
        return "opencti_indicators://test"

    def get_arg(self, name):
        return {"stream_id": "live-1", "import_from": "30"}.get(name)

    def get_global_setting(self, name):
        return {"opencti_url": "https://opencti.test",
                "opencti_api_key": "token"}.get(name)

    def _get_proxy_uri(self):
        return None

    def get_check_point(self, name):
        return self.checkpoints.get(name)

    def save_check_point(self, name, state):
        self.checkpoints[name] = state
        self.saved_checkpoints.append(json.loads(state))

    def log_info(self, message):
        self.logs["info"].append(str(message))

    def log_debug(self, message):
        self.logs["debug"].append(str(message))

    def log_error(self, message):
        self.logs["error"].append(str(message))


INDICATOR = {
    "id": "indicator--7c1e4a90-3f2b-4d55-8a1e-9b0c2d3e4f5a",
    "type": "indicator",
    "name": "Cobalt Strike C2",
    "pattern": "[ipv4-addr:value = '198.51.100.7']",
    "pattern_type": "stix",
    "labels": ["c2", "cobalt-strike"],
    "object_marking_refs": ["marking-definition--tlp-green"],
    "extensions": {
        "extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b": {
            "id": "7c1e4a90-3f2b-4d55-8a1e-9b0c2d3e4f5a",
            "score": 80,
            "detection": True,
        }
    },
}

MARKING = {"id": "marking-definition--tlp-green", "type": "marking-definition", "name": "TLP:GREEN"}
IDENTITY = {"id": "identity--author", "type": "identity", "name": "ACME CTI"}


@pytest.fixture
def run_stream(input_module, monkeypatch):
    """Runs collect_events over a fixed list of stream messages."""

    def run(messages, checkpoint=None, kv_store=None):
        store = kv_store or FakeKVStore()

        class FakeSplunk:
            kvstore = {"opencti_indicators": type("C", (), {"data": store})()}

        monkeypatch.setattr(input_module.client, "connect",
                            lambda **kwargs: FakeSplunk())
        monkeypatch.setattr(input_module, "SSEClient",
                            lambda *args, **kwargs: list(messages))

        helper = StreamHelper(checkpoint)
        input_module.collect_events(helper, None)
        return helper, store

    return run


# --------------------------------------------------------------------------
# writing indicators
# --------------------------------------------------------------------------

def test_a_created_indicator_is_written(run_stream):
    _, store = run_stream([FakeMessage("create", dict(INDICATOR), "1-0")])
    assert len(store.saved) == 1
    assert store.saved[0]["value"] == "198.51.100.7"
    assert store.saved[0]["type"] == "ipv4-addr"


def test_the_record_is_keyed_on_the_opencti_id(run_stream):
    _, store = run_stream([FakeMessage("create", dict(INDICATOR), "1-0")])
    assert store.saved[0]["_key"] == "7c1e4a90-3f2b-4d55-8a1e-9b0c2d3e4f5a"


def test_the_record_is_stamped_with_the_ingestion_time(run_stream):
    _, store = run_stream([FakeMessage("create", dict(INDICATOR), "1-0")])
    assert store.saved[0]["added_at"].endswith("Z")


def test_an_update_overwrites_the_same_key(run_stream):
    updated = dict(INDICATOR, name="Renamed")
    _, store = run_stream([
        FakeMessage("create", dict(INDICATOR), "1-0"),
        FakeMessage("update", updated, "2-0"),
    ])
    assert len(store.rows) == 1, "an update must not create a second row"
    assert store.rows["7c1e4a90-3f2b-4d55-8a1e-9b0c2d3e4f5a"]["name"] == "Renamed"


def test_a_delete_removes_the_row(run_stream):
    _, store = run_stream([
        FakeMessage("create", dict(INDICATOR), "1-0"),
        FakeMessage("delete", dict(INDICATOR), "2-0"),
    ])
    assert store.deleted == ["7c1e4a90-3f2b-4d55-8a1e-9b0c2d3e4f5a"]


def test_deleting_an_unknown_indicator_is_harmless(run_stream):
    _, store = run_stream([FakeMessage("delete", dict(INDICATOR), "1-0")])
    assert store.deleted == []


# --------------------------------------------------------------------------
# labels and markings end to end
# --------------------------------------------------------------------------

def test_every_label_reaches_the_kv_store(run_stream):
    indicator = dict(INDICATOR, labels=["c2", "cobalt-strike", "apt29"])
    _, store = run_stream([FakeMessage("create", indicator, "1-0")])
    assert store.saved[0]["labels"] == ["c2", "cobalt-strike", "apt29"]


def test_a_marking_seen_first_is_resolved(run_stream):
    """The marking definition has to arrive before the indicator that uses it."""
    _, store = run_stream([
        FakeMessage("create", dict(MARKING), "1-0"),
        FakeMessage("create", dict(INDICATOR), "2-0"),
    ])
    assert store.saved[0]["markings"] == ["TLP:GREEN"]


def test_a_marking_not_seen_yet_leaves_the_field_empty(run_stream):
    _, store = run_stream([FakeMessage("create", dict(INDICATOR), "1-0")])
    assert store.saved[0]["markings"] == []


def test_an_identity_is_resolved(run_stream):
    indicator = dict(INDICATOR, created_by_ref="identity--author")
    _, store = run_stream([
        FakeMessage("create", dict(IDENTITY), "1-0"),
        FakeMessage("create", indicator, "2-0"),
    ])
    assert store.saved[0]["created_by"] == "ACME CTI"


# --------------------------------------------------------------------------
# what is skipped
# --------------------------------------------------------------------------

@pytest.mark.parametrize("pattern_type", ["yara", "sigma", "snort", "suricata", "spl", "eql"])
def test_a_non_stix_indicator_is_skipped_and_reported(run_stream, pattern_type):
    indicator = dict(INDICATOR, pattern_type=pattern_type, pattern="rule x {}")
    helper, store = run_stream([FakeMessage("create", indicator, "1-0")])
    assert store.saved == []
    assert any(pattern_type in line for line in helper.logs["info"]), \
        "the skipped indicator has to leave a trace in the log"


def test_an_unsupported_pattern_is_reported_as_an_error(run_stream):
    indicator = dict(INDICATOR, pattern="[software:name = 'BadApp']")
    helper, store = run_stream([FakeMessage("create", indicator, "1-0")])
    assert store.saved == []
    assert any("Unsupported indicator pattern" in line for line in helper.logs["error"])


def test_an_unrelated_stream_event_is_ignored(run_stream):
    _, store = run_stream([FakeMessage("create", {"type": "report", "id": "report--1"}, "1-0")])
    assert store.saved == []


@pytest.mark.parametrize("event", ["heartbeat", "connected"])
def test_a_control_message_is_ignored(run_stream, event):
    _, store = run_stream([FakeMessage(event, {"type": "indicator"}, "1-0")])
    assert store.saved == []


def test_a_failing_write_is_logged_as_an_error(run_stream):
    store = FakeKVStore()
    store.fail_on_save = True
    helper, _ = run_stream([FakeMessage("create", dict(INDICATOR), "1-0")], kv_store=store)
    assert any("Error when processing message" in line for line in helper.logs["error"]), \
        "a rejected record must not be swallowed"


def test_one_bad_message_does_not_stop_the_stream(run_stream):
    _, store = run_stream([
        FakeMessage("create", {"type": "indicator"}, "1-0"),
        FakeMessage("create", dict(INDICATOR), "2-0"),
    ])
    assert len(store.saved) == 1, "the valid indicator after the bad one is still written"


# --------------------------------------------------------------------------
# checkpointing
# --------------------------------------------------------------------------

def test_the_checkpoint_follows_the_last_message(run_stream):
    helper, _ = run_stream([
        FakeMessage("create", dict(INDICATOR), "1-0"),
        FakeMessage("create", dict(MARKING), "2-0"),
    ])
    assert helper.saved_checkpoints[-1]["start_from"] == "2-0"


def test_a_first_run_starts_from_the_import_window(run_stream):
    helper, _ = run_stream([FakeMessage("create", dict(INDICATOR), "1-0")])
    assert helper.saved_checkpoints, "the first run has to write a checkpoint"


def test_an_existing_checkpoint_is_reused(run_stream):
    checkpoint = json.dumps({"start_from": "1700000000000-0"})
    helper, _ = run_stream([FakeMessage("create", dict(INDICATOR), "9-0")], checkpoint=checkpoint)
    assert helper.saved_checkpoints[-1]["start_from"] == "9-0"
