"""Unit tests for the structural STIX pattern parser.

The point of this module is to keep the boolean structure that
Pattern.inspect() throws away, so most of these tests are about telling apart
two patterns that inspect() reports identically.
"""
import pytest

from stix_pattern import (
    AND,
    COMPOSITE_COLLECTION,
    OR,
    SINGLE_COLLECTION,
    classify,
    parse_pattern,
    to_dnf,
    to_kv_row,
)

HASH_AND_NAME = "[file:hashes.'SHA-256' = 'aaa' AND file:name = 'evil.exe']"
HASH_OR_HASH = "[file:hashes.'MD5' = 'bbb' OR file:hashes.'SHA-256' = 'aaa']"
NETWORK_TRIPLE = ("[network-traffic:dst_ref.value = '198.51.100.7' "
                  "AND network-traffic:dst_port = 443 "
                  "AND network-traffic:protocols[*] = 'tcp']")


# --------------------------------------------------------------------------
# structure
# --------------------------------------------------------------------------

def test_and_and_or_are_distinguishable():
    """inspect() reports these two identically, which is why this module exists."""
    conjunction = parse_pattern(HASH_AND_NAME)["observations"][0]["expression"]
    disjunction = parse_pattern(HASH_OR_HASH)["observations"][0]["expression"]
    assert conjunction["operator"] == AND
    assert disjunction["operator"] == OR


def test_single_comparison_has_no_operator():
    expression = parse_pattern("[ipv4-addr:value = '1.2.3.4']")["observations"][0]["expression"]
    assert "operands" not in expression
    assert expression["path"] == "value"


def test_nested_logic_is_preserved():
    pattern = "[file:name = 'a.exe' AND (file:hashes.'MD5' = 'b' OR file:hashes.'SHA-256' = 'c')]"
    expression = parse_pattern(pattern)["observations"][0]["expression"]
    assert expression["operator"] == AND
    nested = [operand for operand in expression["operands"] if "operands" in operand]
    assert len(nested) == 1
    assert nested[0]["operator"] == OR


def test_repeated_operator_is_flattened():
    pattern = "[file:hashes.'MD5' = 'a' AND file:hashes.'SHA-256' = 'b' AND file:name = 'c']"
    expression = parse_pattern(pattern)["observations"][0]["expression"]
    assert expression["operator"] == AND
    assert len(expression["operands"]) == 3


def test_separate_observations_are_kept_apart():
    parsed = parse_pattern("[ipv4-addr:value = '1.2.3.4'] AND [domain-name:value = 'e.test']")
    assert len(parsed["observations"]) == 2
    assert parsed["operator"] == AND


def test_observation_operator_is_reported():
    parsed = parse_pattern("[ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'e.test']")
    assert parsed["operator"] == OR


def test_object_types_are_collected():
    parsed = parse_pattern("[ipv4-addr:value = '1.2.3.4' AND network-traffic:dst_port = 443]")
    assert parsed["observations"][0]["object_types"] == ["ipv4-addr", "network-traffic"]


# --------------------------------------------------------------------------
# comparison details
# --------------------------------------------------------------------------

@pytest.mark.parametrize("pattern, operator", [
    ("[ipv4-addr:value = '1.2.3.4']", "="),
    ("[ipv4-addr:value != '1.2.3.4']", "!="),
    ("[domain-name:value LIKE 'evil%']", "LIKE"),
    ("[url:value MATCHES 'evil']", "MATCHES"),
    ("[ipv4-addr:value IN ('1.2.3.4', '5.6.7.8')]", "IN"),
])
def test_comparison_operator_is_captured(pattern, operator):
    comparison = parse_pattern(pattern)["observations"][0]["comparisons"][0]
    assert comparison["operator"] == operator


def test_quoted_path_component_is_normalized():
    comparison = parse_pattern("[file:hashes.'SHA-256' = 'aaa']")["observations"][0]["comparisons"][0]
    assert comparison["path"] == "hashes.SHA-256"


def test_list_index_path_is_kept_as_text():
    comparison = parse_pattern("[network-traffic:protocols[*] = 'tcp']")["observations"][0]["comparisons"][0]
    assert comparison["path"] == "protocols[*]"


@pytest.mark.parametrize("pattern, expected", [
    (r"[windows-registry-key:key = 'HKLM\\Software\\Evil']", r"HKLM\Software\Evil"),
    (r"[file:name = 'O\'Brien.doc']", "O'Brien.doc"),
    ("[file:name = 'plain.exe']", "plain.exe"),
])
def test_value_is_unescaped(pattern, expected):
    comparison = parse_pattern(pattern)["observations"][0]["comparisons"][0]
    assert comparison["value"] == expected


# --------------------------------------------------------------------------
# disjunctive normal form
# --------------------------------------------------------------------------

@pytest.mark.parametrize("pattern, shape", [
    ("[ipv4-addr:value = '1.2.3.4']", [1]),
    (HASH_AND_NAME, [2]),
    (HASH_OR_HASH, [1, 1]),
    ("[file:name = 'a.exe' AND (file:hashes.'MD5' = 'b' OR file:hashes.'SHA-256' = 'c')]", [2, 2]),
    (NETWORK_TRIPLE, [3]),
])
def test_to_dnf_shape(pattern, shape):
    """Each alternative is a row, each of its terms a column of that row."""
    expression = parse_pattern(pattern)["observations"][0]["expression"]
    assert [len(alternative) for alternative in to_dnf(expression)] == shape


def test_to_dnf_distributes_over_or():
    pattern = "[file:name = 'a.exe' AND (file:hashes.'MD5' = 'b' OR file:hashes.'SHA-256' = 'c')]"
    alternatives = to_dnf(parse_pattern(pattern)["observations"][0]["expression"])
    for alternative in alternatives:
        paths = sorted(comparison["path"] for comparison in alternative)
        assert "name" in paths, "the shared term is repeated in every alternative"


# --------------------------------------------------------------------------
# classification and routing
# --------------------------------------------------------------------------

@pytest.mark.parametrize("pattern, strategy, collection", [
    ("[ipv4-addr:value = '1.2.3.4']", "single_value", SINGLE_COLLECTION),
    ("[file:hashes.'SHA-256' = 'aaa']", "single_value", SINGLE_COLLECTION),
    (HASH_OR_HASH, "single_value", SINGLE_COLLECTION),
    (HASH_AND_NAME, "attribute_set", COMPOSITE_COLLECTION),
    (NETWORK_TRIPLE, "attribute_set", COMPOSITE_COLLECTION),
    ("[ipv4-addr:value = '1.2.3.4' AND network-traffic:dst_port = 443]",
     "attribute_set", COMPOSITE_COLLECTION),
    ("[domain-name:value = 'e.test' AND network-traffic:dst_port = 8080]",
     "attribute_set", COMPOSITE_COLLECTION),
    ("[ipv4-addr:value = '1.2.3.4'] AND [domain-name:value = 'e.test']", "correlation", None),
    ("[software:name = 'x' AND file:name = 'y']", "correlation", None),
    ("[file:hashes.'MD5' = 'b' AND file:hashes.'SHA-256' = 'a']", "correlation", None),
    ("[domain-name:value LIKE 'evil%']", "unsupported", None),
    ("[ipv4-addr:value != '1.2.3.4']", "unsupported", None),
])
def test_classify_routes_to_the_right_collection(pattern, strategy, collection):
    result = classify(parse_pattern(pattern))
    assert result["strategy"] == strategy
    assert result["collection"] == collection


def test_classify_always_explains_itself():
    for pattern in [HASH_AND_NAME, HASH_OR_HASH, "[domain-name:value LIKE 'e%']"]:
        assert classify(parse_pattern(pattern))["reason"]


def test_alternatives_of_one_attribute_stay_in_the_single_collection():
    """An OR of plain values is several ordinary rows, not a composite one."""
    result = classify(parse_pattern(HASH_OR_HASH))
    assert result["collection"] == SINGLE_COLLECTION
    assert len(result["alternatives"]) == 2


# --------------------------------------------------------------------------
# KV store rows
# --------------------------------------------------------------------------

def test_to_kv_row_names_the_columns_after_cim():
    alternative = classify(parse_pattern(HASH_AND_NAME))["alternatives"][0]
    columns, unmapped, conflicts = to_kv_row(alternative)
    assert columns == {"file_hash": "aaa", "file_name": "evil.exe"}
    assert not unmapped and not conflicts


def test_to_kv_row_handles_network_traffic():
    alternative = classify(parse_pattern(NETWORK_TRIPLE))["alternatives"][0]
    columns, _, _ = to_kv_row(alternative)
    assert columns == {"dest_ip": "198.51.100.7", "dest_port": "443", "transport": "tcp"}


def test_to_kv_row_maps_a_lone_address_to_the_destination():
    pattern = "[ipv4-addr:value = '198.51.100.7' AND network-traffic:dst_port = 443]"
    alternative = classify(parse_pattern(pattern))["alternatives"][0]
    columns, _, _ = to_kv_row(alternative)
    assert columns == {"dest_ip": "198.51.100.7", "dest_port": "443"}


def test_to_kv_row_reports_an_unmapped_attribute():
    alternative = to_dnf(parse_pattern("[software:name = 'x' AND file:name = 'y']")
                         ["observations"][0]["expression"])[0]
    _, unmapped, _ = to_kv_row(alternative)
    assert unmapped == ["software:name"]


def test_to_kv_row_reports_a_cim_field_claimed_twice():
    """CIM has one file_hash, so two hash types cannot be required together."""
    pattern = "[file:hashes.'MD5' = 'b' AND file:hashes.'SHA-256' = 'a']"
    alternative = to_dnf(parse_pattern(pattern)["observations"][0]["expression"])[0]
    _, _, conflicts = to_kv_row(alternative)
    assert conflicts == ["file_hash"]


def test_to_kv_row_accepts_the_same_value_twice():
    pattern = "[file:hashes.'MD5' = 'b' AND file:hashes.'MD5' = 'b']"
    alternative = to_dnf(parse_pattern(pattern)["observations"][0]["expression"])[0]
    columns, _, conflicts = to_kv_row(alternative)
    assert conflicts == []
    assert columns == {"file_hash": "b"}
