"""Locks the set of indicators the add-on ingests.

Coverage is a deliberate choice, not an accident. Any change to the observable
types, the attribute paths or the accepted operators has to show up as a
failure here and be acknowledged by updating the table.
"""
import pytest

# Attribute path -> value of the "type" column in the KV store.
# Adding support for something means adding a line here as well.
EXPECTED_COVERAGE = {
    "[autonomous-system:number = 64496]": ("autonomous-system", "64496"),
    "[cryptocurrency-wallet:value = '1A1zP1eP5Q']": ("cryptocurrency-wallet", "1A1zP1eP5Q"),
    "[directory:path = '/tmp/evil']": ("directory", "/tmp/evil"),
    "[domain-name:value = 'evil.test']": ("domain-name", "evil.test"),
    "[email-addr:value = 'a@evil.test']": ("email-addr", "a@evil.test"),
    "[email-message:subject = 'invoice']": ("email-message", "invoice"),
    "[hostname:value = 'WKS-001']": ("hostname", "WKS-001"),
    "[ipv4-addr:value = '198.51.100.7']": ("ipv4-addr", "198.51.100.7"),
    "[ipv6-addr:value = '2001:db8::1']": ("ipv6-addr", "2001:db8::1"),
    "[mac-addr:value = '00:11:22:33:44:55']": ("mac-addr", "00:11:22:33:44:55"),
    "[mutex:name = 'evil_mutex']": ("mutex", "evil_mutex"),
    "[phone-number:value = '+33123456789']": ("phone-number", "+33123456789"),
    "[text:value = 'a note']": ("text", "a note"),
    "[url:value = 'http://evil.test/a']": ("url", "http://evil.test/a"),
    "[user-account:account_login = 'jdoe']": ("user-account", "jdoe"),
    "[user-agent:value = 'Mozilla/5.0']": ("user-agent", "Mozilla/5.0"),
    "[windows-registry-key:key = 'HKLM\\\\Run']": ("windows-registry-key", "HKLM\\Run"),
    "[file:name = 'invoice.exe']": ("filename", "invoice.exe"),
    "[file:hashes.'MD5' = '%s']" % ("d" * 32): ("md5", "d" * 32),
    "[file:hashes.'SHA-1' = '%s']" % ("e" * 40): ("sha1", "e" * 40),
    "[file:hashes.'SHA-256' = '%s']" % ("f" * 64): ("sha256", "f" * 64),
    "[file:hashes.'SHA-512' = '%s']" % ("a" * 128): ("sha512", "a" * 128),
}

# Known not to be ingested. Moving one of these to EXPECTED_COVERAGE is a
# feature, moving one the other way is a regression.
EXPECTED_GAPS = [
    "[network-traffic:dst_port = 4444]",
    "[process:command_line = 'evil.exe -x']",
    "[software:name = 'BadApp']",
    "[x509-certificate:serial_number = '00:11']",
    "[bank-account:iban = 'FR761234']",
    "[payment-card:card_number = '4111111111111111']",
    "[media-content:url = 'http://evil.test/p']",
]


@pytest.mark.parametrize("pattern", sorted(EXPECTED_COVERAGE))
def test_pattern_is_still_ingested(input_module, pattern):
    expected_type, expected_value = EXPECTED_COVERAGE[pattern]
    parsed = input_module.parse_stix_pattern(pattern)
    assert parsed is not None, "this indicator used to be ingested"
    assert (parsed["type"], parsed["value"]) == (expected_type, expected_value)


@pytest.mark.parametrize("pattern", EXPECTED_GAPS)
def test_known_gap_is_still_a_gap(input_module, pattern):
    """Fails when a type starts being ingested without the table being updated."""
    assert input_module.parse_stix_pattern(pattern) is None


def test_coverage_count_is_unchanged(input_module):
    supported = sum(1 for pattern in EXPECTED_COVERAGE
                    if input_module.parse_stix_pattern(pattern) is not None)
    assert supported == len(EXPECTED_COVERAGE) == 22


def test_every_supported_type_appears_in_the_table(input_module):
    """The table has to describe every entry of SUPPORTED_TYPES."""
    declared = {kv_type
                for paths in input_module.SUPPORTED_TYPES.values()
                for kv_type in paths.values()}
    covered = {kv_type for kv_type, _ in EXPECTED_COVERAGE.values()}
    assert declared == covered, "SUPPORTED_TYPES and the coverage table disagree"


@pytest.mark.parametrize("pattern", [
    "[ipv4-addr:value != '198.51.100.7']",
    "[domain-name:value LIKE 'evil%']",
    "[url:value MATCHES 'evil']",
    "[ipv4-addr:value IN ('198.51.100.7', '198.51.100.8')]",
])
def test_only_equality_is_ingested(input_module, pattern):
    assert input_module.parse_stix_pattern(pattern) is None


def test_a_compound_pattern_keeps_one_value(input_module):
    """Documents the current limitation: only the first observable is stored."""
    pattern = "[file:hashes.'SHA-256' = '%s' OR file:hashes.'MD5' = '%s']" % ("f" * 64, "d" * 32)
    parsed = input_module.parse_stix_pattern(pattern)
    assert parsed is not None
    assert parsed["type"] in ("sha256", "md5"), "one of the two hashes is kept, not both"
