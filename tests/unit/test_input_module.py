"""Unit tests for the indicators modular input."""
import pytest


# --------------------------------------------------------------------------
# normalize_multi_valued
# --------------------------------------------------------------------------

@pytest.mark.parametrize("given, expected", [
    (None, []),
    ([], []),
    ("solo", ["solo"]),
    (["solo"], ["solo"]),
    (["a", "b"], ["a", "b"]),
    (["  a  ", "b "], ["a", "b"]),
    (["a", "", "   ", None, "b"], ["a", "b"]),
    (["a", "a"], ["a", "a"]),
    ([1, 2], ["1", "2"]),
    (["hameçon", "рансом"], ["hameçon", "рансом"]),
])
def test_normalize_multi_valued(input_module, given, expected):
    assert input_module.normalize_multi_valued(given) == expected


@pytest.mark.parametrize("count", [0, 1, 2, 3, 10, 25, 50, 200])
def test_normalize_multi_valued_keeps_every_value(input_module, count):
    """No value is lost whatever the number of them."""
    values = ["label-%03d" % i for i in range(count)]
    assert input_module.normalize_multi_valued(values) == values


# --------------------------------------------------------------------------
# unquote_stix_value
# --------------------------------------------------------------------------

@pytest.mark.parametrize("literal, expected", [
    ("'plain.exe'", "plain.exe"),
    ("'198.51.100.7'", "198.51.100.7"),
    ("443", "443"),
    ("''", ""),
    (r"'HKLM\\Software\\Evil'", r"HKLM\Software\Evil"),
    (r"'C:\\Temp\\evil'", r"C:\Temp\evil"),
    (r"'O\'Brien.doc'", "O'Brien.doc"),
    (r"'ends with a backslash\\'", "ends with a backslash" + "\\"),
])
def test_unquote_stix_value(input_module, literal, expected):
    assert input_module.unquote_stix_value(literal) == expected


# --------------------------------------------------------------------------
# parse_stix_pattern
# --------------------------------------------------------------------------

SUPPORTED_PATTERNS = [
    ("[ipv4-addr:value = '198.51.100.7']", "ipv4-addr", "198.51.100.7"),
    ("[ipv6-addr:value = '2001:db8::1']", "ipv6-addr", "2001:db8::1"),
    ("[domain-name:value = 'evil.test']", "domain-name", "evil.test"),
    ("[hostname:value = 'WKS-001']", "hostname", "WKS-001"),
    ("[url:value = 'http://evil.test/a']", "url", "http://evil.test/a"),
    ("[email-addr:value = 'a@evil.test']", "email-addr", "a@evil.test"),
    ("[email-message:subject = 'invoice']", "email-message", "invoice"),
    ("[user-agent:value = 'Mozilla/5.0']", "user-agent", "Mozilla/5.0"),
    ("[mac-addr:value = '00:11:22:33:44:55']", "mac-addr", "00:11:22:33:44:55"),
    ("[mutex:name = 'evil_mutex']", "mutex", "evil_mutex"),
    ("[directory:path = '/tmp/evil']", "directory", "/tmp/evil"),
    ("[autonomous-system:number = 64496]", "autonomous-system", "64496"),
    ("[user-account:account_login = 'jdoe']", "user-account", "jdoe"),
    ("[cryptocurrency-wallet:value = '1A1zP1eP5Q']", "cryptocurrency-wallet", "1A1zP1eP5Q"),
    ("[phone-number:value = '+33123456789']", "phone-number", "+33123456789"),
    ("[text:value = 'a note']", "text", "a note"),
    ("[file:name = 'invoice.exe']", "filename", "invoice.exe"),
    ("[file:hashes.'MD5' = '%s']" % ("d" * 32), "md5", "d" * 32),
    ("[file:hashes.'SHA-1' = '%s']" % ("e" * 40), "sha1", "e" * 40),
    ("[file:hashes.'SHA-256' = '%s']" % ("f" * 64), "sha256", "f" * 64),
    ("[file:hashes.'SHA-512' = '%s']" % ("a" * 128), "sha512", "a" * 128),
    ("[windows-registry-key:key = 'HKLM\\\\Run']", "windows-registry-key", "HKLM\\Run"),
]


@pytest.mark.parametrize("pattern, expected_type, expected_value", SUPPORTED_PATTERNS)
def test_parse_stix_pattern_supported(input_module, pattern, expected_type, expected_value):
    parsed = input_module.parse_stix_pattern(pattern)
    assert parsed is not None, "pattern should be ingested"
    assert parsed["type"] == expected_type
    assert parsed["value"] == expected_value


@pytest.mark.parametrize("pattern", [
    "[network-traffic:dst_port = 443]",
    "[process:command_line = 'evil.exe']",
    "[software:name = 'BadApp']",
    "[x509-certificate:serial_number = '00:11']",
])
def test_parse_stix_pattern_unsupported_type_is_skipped(input_module, pattern):
    assert input_module.parse_stix_pattern(pattern) is None


@pytest.mark.parametrize("pattern", [
    "[ipv4-addr:value != '198.51.100.7']",
    "[domain-name:value LIKE 'evil%']",
    "[url:value MATCHES 'evil']",
    "[ipv4-addr:value IN ('198.51.100.7', '198.51.100.8')]",
])
def test_parse_stix_pattern_only_equality_is_ingested(input_module, pattern):
    assert input_module.parse_stix_pattern(pattern) is None


@pytest.mark.parametrize("pattern", [
    "[windows-registry-key:values[*].name = 'Run']",
    "[email-message:body_multipart[*].body = 'x']",
])
def test_parse_stix_pattern_list_index_does_not_crash(input_module, pattern):
    """A path pointing into a list is skipped instead of raising a TypeError."""
    assert input_module.parse_stix_pattern(pattern) is None


def test_parse_stix_pattern_list_index_does_not_hide_a_match(input_module):
    """A list index earlier in the pattern must not stop the supported one."""
    pattern = "[windows-registry-key:values[*].name = 'Run' AND windows-registry-key:key = 'HKLM\\\\Evil']"
    parsed = input_module.parse_stix_pattern(pattern)
    assert parsed == {"type": "windows-registry-key", "value": "HKLM\\Evil"}


# --------------------------------------------------------------------------
# enrich_payload
# --------------------------------------------------------------------------

def test_enrich_payload_keeps_every_label(markings, helper, stream_indicator):
    stream_indicator["labels"] = ["c2", "cobalt-strike", "apt29"]
    record = markings.enrich_payload(helper, stream_indicator)
    assert record["labels"] == ["c2", "cobalt-strike", "apt29"]


def test_enrich_payload_keeps_every_marking(markings, helper, stream_indicator):
    """Two markings on the indicator give two markings in the record."""
    record = markings.enrich_payload(helper, stream_indicator)
    assert record["markings"] == ["TLP:GREEN", "PAP:AMBER"]


def test_enrich_payload_keeps_every_indicator_type(markings, helper, stream_indicator):
    record = markings.enrich_payload(helper, stream_indicator)
    assert record["indicator_types"] == ["malicious-activity", "attribution"]


@pytest.mark.parametrize("field", ["labels", "markings", "indicator_types"])
def test_enrich_payload_multi_valued_fields_are_always_lists(
        markings, helper, stream_indicator, field):
    stream_indicator.pop("labels", None)
    stream_indicator.pop("indicator_types", None)
    stream_indicator["object_marking_refs"] = []
    record = markings.enrich_payload(helper, stream_indicator)
    assert record[field] == []


def test_enrich_payload_skips_unknown_markings(markings, helper, stream_indicator):
    stream_indicator["object_marking_refs"] = [
        "marking-definition--not-seen-yet",
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    ]
    record = markings.enrich_payload(helper, stream_indicator)
    assert record["markings"] == ["TLP:GREEN"]


def test_enrich_payload_resolves_the_author(markings, helper, stream_indicator):
    record = markings.enrich_payload(helper, stream_indicator)
    assert record["created_by"] == "ACME CTI"


def test_enrich_payload_sets_the_key_from_the_extension(markings, helper, stream_indicator):
    record = markings.enrich_payload(helper, stream_indicator)
    assert record["_key"] == "7c1e4a90-3f2b-4d55-8a1e-9b0c2d3e4f5a"


def test_enrich_payload_exposes_the_pattern_as_type_and_value(markings, helper, stream_indicator):
    record = markings.enrich_payload(helper, stream_indicator)
    assert record["type"] == "ipv4-addr"
    assert record["value"] == "198.51.100.7"


def test_enrich_payload_lifts_the_extension_attributes(markings, helper, stream_indicator):
    record = markings.enrich_payload(helper, stream_indicator)
    assert record["score"] == 80
    assert record["detection"] is True
    assert record["main_observable_type"] == "IPv4-Addr"
    assert "extensions" not in record


def test_enrich_payload_defaults_detection_to_false(markings, helper, stream_indicator):
    extension = stream_indicator["extensions"]["extension-definition--322b8f77-262a-4cb8-a915-1e441e00329b"]
    del extension["detection"]
    record = markings.enrich_payload(helper, stream_indicator)
    assert record["detection"] is False


def test_enrich_payload_drops_external_references(markings, helper, stream_indicator):
    record = markings.enrich_payload(helper, stream_indicator)
    assert "external_references" not in record


def test_enrich_payload_returns_none_for_an_unsupported_pattern(markings, helper, stream_indicator):
    stream_indicator["pattern"] = "[software:name = 'BadApp']"
    assert markings.enrich_payload(helper, stream_indicator) is None


def test_enrich_payload_tags_the_input(markings, helper, stream_indicator):
    record = markings.enrich_payload(helper, stream_indicator)
    assert record["stream_id"] == "live-stream-1"
    assert record["input_name"] == "opencti_indicators://test"
