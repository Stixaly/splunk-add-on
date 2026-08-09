"""Structural parser for STIX patterns.

``Pattern.inspect()`` flattens a pattern into a set of comparisons grouped by
observable type, and drops the boolean operators used inside an observation
expression. That makes two patterns needing opposite handling look identical::

    [file:hashes.'MD5' = 'a' AND file:name = 'b']   one file, two attributes
    [file:hashes.'MD5' = 'a' OR  file:name = 'b']   two independent indicators

Both are reported by ``inspect()`` as the same two comparisons on ``file``.

This module walks the parse tree instead and keeps the structure, so a caller
can tell an AND from an OR, and knows which comparisons belong to the same
observation expression.
"""

from stix2patterns.v21.grammars.STIXPatternListener import STIXPatternListener
from stix2patterns.v21.pattern import Pattern

AND = "AND"
OR = "OR"

# KV store collection an indicator is routed to, None when it cannot be
# matched by a lookup alone
SINGLE_COLLECTION = "opencti_indicators"
COMPOSITE_COLLECTION = "opencti_indicators_composite"


def _literal_to_value(text):
    """Turn a pattern literal into the value it represents

    :param text: literal as written in the pattern, quoted or not
    :return: the value, without its quotes and without STIX escaping
    """
    if len(text) >= 2 and text.startswith("'") and text.endswith("'"):
        text = text[1:-1]

    value = []
    escaped = False
    for character in text:
        if escaped:
            value.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            value.append(character)
    return "".join(value)


def _split_object_path(object_path_ctx):
    """Split an object path into its observable type and its attribute path

    ``file:hashes.'MD5'`` gives ``("file", "hashes.MD5")``. The quotes around a
    path component are removed so the result can be compared with a plain
    attribute name.

    :param object_path_ctx: objectPath parse tree node
    :return: tuple (observable type, attribute path)
    """
    observable_type, _, path = object_path_ctx.getText().partition(":")
    components = [component.strip("'") for component in path.split(".")]
    return observable_type, ".".join(components)


def _combine(operator, operands):
    """Group operands under an operator, flattening the nested same operator

    :param operator: AND or OR
    :param operands: list of nodes
    :return: the resulting node
    """
    flattened = []
    for operand in operands:
        if operand.get("operator") == operator and "operands" in operand:
            flattened.extend(operand["operands"])
        else:
            flattened.append(operand)
    return {"operator": operator, "operands": flattened}


class _PatternListener(STIXPatternListener):
    """Rebuilds the pattern structure while the parse tree is walked

    The parse tree is walked bottom up, so every node is pushed on a stack as
    soon as it is complete, and an operator pops the operands it applies to.
    """

    def __init__(self):
        self.comparisons = []
        self.observations = []
        self.observation_operators = []

    # --- leaves: one attribute compared with one value -------------------

    def _push_comparison(self, ctx, operator):
        observable_type, path = _split_object_path(ctx.objectPath())
        self.comparisons.append({
            "object_type": observable_type,
            "path": path,
            "operator": operator,
            "value": _literal_to_value(ctx.getChild(ctx.getChildCount() - 1).getText()),
            "negated": ctx.NOT() is not None,
        })

    def exitPropTestEqual(self, ctx):
        self._push_comparison(ctx, "!=" if ctx.NEQ() else "=")

    def exitPropTestOrder(self, ctx):
        self._push_comparison(ctx, ctx.getChild(1).getText())

    def exitPropTestLike(self, ctx):
        self._push_comparison(ctx, "LIKE")

    def exitPropTestRegex(self, ctx):
        self._push_comparison(ctx, "MATCHES")

    def exitPropTestSet(self, ctx):
        self._push_comparison(ctx, "IN")

    def exitPropTestIsSubset(self, ctx):
        self._push_comparison(ctx, "ISSUBSET")

    def exitPropTestIsSuperset(self, ctx):
        self._push_comparison(ctx, "ISSUPERSET")

    def exitPropTestExists(self, ctx):
        observable_type, path = _split_object_path(ctx.objectPath())
        self.comparisons.append({
            "object_type": observable_type,
            "path": path,
            "operator": "EXISTS",
            "value": None,
            "negated": ctx.NOT() is not None,
        })

    # --- operators inside one observation expression ---------------------

    def exitComparisonExpressionAnd(self, ctx):
        if ctx.AND() is not None:
            right = self.comparisons.pop()
            left = self.comparisons.pop()
            self.comparisons.append(_combine(AND, [left, right]))

    def exitComparisonExpression(self, ctx):
        if ctx.OR() is not None:
            right = self.comparisons.pop()
            left = self.comparisons.pop()
            self.comparisons.append(_combine(OR, [left, right]))

    # --- observation expressions -----------------------------------------

    def exitObservationExpressionSimple(self, ctx):
        self.observations.append(self.comparisons.pop())

    def exitObservationExpressionAnd(self, ctx):
        if ctx.AND() is not None:
            self.observation_operators.append(AND)

    def exitObservationExpressionOr(self, ctx):
        if ctx.OR() is not None:
            self.observation_operators.append(OR)


def _walk(node, found):
    """Collect every comparison of an expression tree

    :param node: expression node
    :param found: list the comparisons are appended to
    """
    if "operands" in node:
        for operand in node["operands"]:
            _walk(operand, found)
    else:
        found.append(node)


# Splunk CIM field each STIX attribute is compared with. Only the observables
# carrying several attributes are listed: a lone address or domain is stored in
# the single value collection, where the search picks the field to match on.
CIM_FIELDS = {
    ("file", "hashes.MD5"): "file_hash",
    ("file", "hashes.SHA-1"): "file_hash",
    ("file", "hashes.SHA-256"): "file_hash",
    ("file", "hashes.SHA-512"): "file_hash",
    ("file", "name"): "file_name",
    ("file", "parent_directory_ref.path"): "file_path",
    ("network-traffic", "src_ref.value"): "src_ip",
    ("network-traffic", "dst_ref.value"): "dest_ip",
    ("network-traffic", "src_port"): "src_port",
    ("network-traffic", "dst_port"): "dest_port",
    ("network-traffic", "protocols[*]"): "transport",
    ("windows-registry-key", "key"): "registry_key_name",
    ("windows-registry-key", "values[*].name"): "registry_value_name",
    ("process", "command_line"): "process",
    ("process", "name"): "process",
    ("email-message", "subject"): "subject",
    ("email-message", "from_ref.value"): "src_user",
    ("email-message", "to_refs[*].value"): "recipient",
    ("url", "value"): "url",
    ("domain-name", "value"): "url_domain",
    ("user-account", "account_login"): "user",
    ("user-agent", "value"): "http_user_agent",
    # A lone address carries no direction. STIX puts it in its own object even
    # when the pattern also constrains a port, as in
    # [ipv4-addr:value = '...' AND network-traffic:dst_port = ...], so it is
    # read as the destination, which is what such an indicator describes in
    # practice. Change these two entries to src_ip to read them the other way.
    ("ipv4-addr", "value"): "dest_ip",
    ("ipv6-addr", "value"): "dest_ip",
    ("mac-addr", "value"): "dest_mac",
    ("email-addr", "value"): "src_user",
    ("hostname", "value"): "dest",
}


def to_kv_row(alternative):
    """Turn one alternative into the columns of a composite KV store row

    :param alternative: list of comparisons that all have to match
    :return: tuple (columns, unmapped, conflicts) where columns maps a CIM
        field to its value, unmapped lists the attributes with no CIM field,
        and conflicts lists the CIM fields claimed by several attributes
    """
    columns = {}
    unmapped = []
    conflicts = []
    for comparison in alternative:
        cim_field = CIM_FIELDS.get((comparison["object_type"], comparison["path"]))
        if cim_field is None:
            unmapped.append("%s:%s" % (comparison["object_type"], comparison["path"]))
        elif cim_field in columns and columns[cim_field] != comparison["value"]:
            conflicts.append(cim_field)
        else:
            columns[cim_field] = comparison["value"]
    return columns, unmapped, sorted(set(conflicts))


def to_dnf(node):
    """Rewrite an expression as a list of alternatives, each a list of terms

    The expression is put in disjunctive normal form, that is an OR of ANDs.
    Every alternative is then independently sufficient to consider the
    indicator seen, and the terms of an alternative all have to be matched::

        [a]                 -> [[a]]
        [a AND b]           -> [[a, b]]
        [a OR b]            -> [[a], [b]]
        [a AND (b OR c)]    -> [[a, b], [a, c]]

    That maps directly onto the KV store: one alternative is one row, and the
    terms of that alternative are the columns to match together.

    :param node: expression node
    :return: list of alternatives, each a list of comparisons
    """
    if "operands" not in node:
        return [[node]]

    if node["operator"] == OR:
        alternatives = []
        for operand in node["operands"]:
            alternatives.extend(to_dnf(operand))
        return alternatives

    # AND: combine every alternative of an operand with every alternative
    # of the operands already processed
    alternatives = [[]]
    for operand in node["operands"]:
        combined = []
        for existing in alternatives:
            for addition in to_dnf(operand):
                combined.append(existing + addition)
        alternatives = combined
    return alternatives


def classify(parsed):
    """Decide how a parsed pattern can be stored and matched in Splunk

    :param parsed: result of parse_pattern
    :return: dict with the strategy, the alternatives and a reason
    """
    observations = parsed["observations"]

    if len(observations) != 1:
        return {
            "strategy": "correlation",
            "collection": None,
            "alternatives": [],
            "reason": "%d observation expressions joined by %s, matching them needs "
                      "a search over a time window" % (len(observations), parsed["operator"]),
        }

    alternatives = to_dnf(observations[0]["expression"])

    unsupported = sorted({c["operator"] for a in alternatives for c in a} - {"="})
    if unsupported:
        return {
            "strategy": "unsupported",
            "collection": None,
            "alternatives": alternatives,
            "reason": "comparison operator(s) %s cannot be matched by a lookup"
                      % ", ".join(unsupported),
        }

    # Several attributes only match together when each one maps to its own CIM
    # field, so that a single event can carry all of them. The observable types
    # they come from do not matter: an address and a port live in two STIX
    # objects but in the same CIM event.
    for alternative in alternatives:
        if len(alternative) == 1:
            continue
        _, unmapped, conflicts = to_kv_row(alternative)
        if unmapped:
            return {
                "strategy": "correlation",
                "collection": None,
                "alternatives": alternatives,
                "reason": "no CIM field is known for %s, so it cannot be matched "
                          "alongside the other attributes" % ", ".join(sorted(set(unmapped))),
            }
        if conflicts:
            return {
                "strategy": "correlation",
                "collection": None,
                "alternatives": alternatives,
                "reason": "several attributes map to the CIM field %s, a single event "
                          "only carries one of them" % ", ".join(conflicts),
            }

    # an alternative matching a single attribute is what the single value
    # collection already stores, even when the pattern offers several of them
    if all(len(alternative) == 1 for alternative in alternatives):
        return {
            "strategy": "single_value",
            "collection": SINGLE_COLLECTION,
            "alternatives": alternatives,
            "reason": "%d alternative(s) of one attribute, each is a row of the single "
                      "value collection" % len(alternatives),
        }

    return {
        "strategy": "attribute_set",
        "collection": COMPOSITE_COLLECTION,
        "alternatives": alternatives,
        "reason": "%d alternative(s) matching %s attribute(s) together"
                  % (len(alternatives), "/".join(str(len(a)) for a in alternatives)),
    }


def parse_pattern(pattern_str):
    """Parse a STIX pattern and keep its structure

    :param pattern_str: the STIX pattern
    :return: dict with the observations and the operator joining them
    :raises: the parser exceptions when the pattern is invalid
    """
    listener = _PatternListener()
    Pattern(pattern_str).walk(listener)

    observations = []
    for expression in listener.observations:
        comparisons = []
        _walk(expression, comparisons)
        observations.append({
            "expression": expression,
            "comparisons": comparisons,
            "object_types": sorted({c["object_type"] for c in comparisons}),
        })

    operators = set(listener.observation_operators)
    return {
        "observations": observations,
        "operator": operators.pop() if len(operators) == 1 else (AND if operators else None),
    }
