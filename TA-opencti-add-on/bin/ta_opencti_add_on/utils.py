import datetime
import ipaddress
import re
import uuid
from stix2.canonicalization.Canonicalize import canonicalize

regex_sha512 = r"[0-9a-fA-F]{128}"
regex_sha256 = r"[0-9a-fA-F]{64}"
regex_sha1 = r"[0-9a-fA-F]{40}"
regex_md5 = r"[0-9a-fA-F]{32}"

def get_proxy_config(helper):
    """
    :param helper:
    :return:
    """
    proxy_uri = helper._get_proxy_uri()
    if proxy_uri:
        return {
            "http": proxy_uri,
            "https": proxy_uri
        }
    else:
        return None

def is_ipv6(value: str):
    """
    Determine whether the provided string is an IPv6 address or valid IPv6 CIDR.
    :param value:
    :return:
    """
    try:
        ipaddress.IPv6Address(value)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Network(value, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def is_ipv4(value: str):
    """
    Determine whether the provided string is an IPv4 address or valid IPv4 CIDR.
    :param value:
    :return:
    """
    try:
        ipaddress.IPv4Address(value)  # Check for individual IP
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv4Network(value, strict=False)  # Check for CIDR notation
            return True
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            return False


def get_hash_type(value: str):
    """
    :param value:
    :return:
    """
    if re.match(regex_sha512, value):
        return "sha512"
    elif re.match(regex_sha256, value):
        return "sha256"
    elif re.match(regex_sha1, value):
        return "sha1"
    elif re.match(regex_md5, value):
        return "md5"
    else:
        return None

_TZ_OFFSET_WITHOUT_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def _parse_whole_number(value, label):
    """Read a whole number given to an alert action.

    The value comes from a Splunk token, so it is usually a string and may be
    empty, which gives None.

    :param value:
    :param label: name of the parameter, for the error message
    :return: an int, or None for an empty value
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise Exception(f"Invalid {label}: {value!r}, a whole number is expected")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text == "":
        return None
    try:
        number = float(text)
    except ValueError:
        raise Exception(f"Invalid {label}: {value!r}, a whole number is expected")
    if not number.is_integer():
        raise Exception(f"Invalid {label}: {value!r}, a whole number is expected")
    return int(number)


def parse_count(value, default=1):
    """Parse the count given to the sighting alert action.

    An empty value falls back to the default, anything else has to be a whole,
    non-negative number.

    :param value:
    :param default:
    :return:
    """
    count = _parse_whole_number(value, "count")
    if count is None:
        return default
    if count < 0:
        raise Exception(f"Invalid count: {value!r}, it cannot be negative")
    return count


def parse_score(value):
    """Parse the score to give a sighted indicator.

    :param value:
    :return: an int between 0 and 100, or None for an empty value
    """
    score = _parse_whole_number(value, "score")
    if score is not None and not 0 <= score <= 100:
        raise Exception(f"Invalid score: {value!r}, a whole number between 0 and 100 is expected")
    return score


def parse_days(value):
    """Parse a number of days of validity to give a sighted indicator.

    :param value:
    :return: an int of at least 1, or None for an empty value
    """
    days = _parse_whole_number(value, "number of days")
    if days is not None and days < 1:
        raise Exception(f"Invalid number of days: {value!r}, at least 1 is expected")
    return days


def parse_timestamp(value):
    """Parse a date given to an alert action.

    The value is accepted as an epoch in seconds, which is the form of the
    Splunk _time field and of min(_time) / max(_time), or as an ISO 8601 date
    with an optional fraction and offset. A date without offset is read as UTC.

    :param value:
    :return: an aware datetime in UTC, or None when the value is empty
    """
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=datetime.timezone.utc)
        return value
    text = str(value).strip()
    if text == "":
        return None
    try:
        return datetime.datetime.fromtimestamp(float(text), datetime.timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    iso = text
    if iso[-1] in "zZ":
        iso = iso[:-1] + "+00:00"
    # "+0200", as Splunk's strftime %z writes it, is not accepted before Python 3.11
    iso = _TZ_OFFSET_WITHOUT_COLON.sub(r"\1:\2", iso)
    try:
        parsed = datetime.datetime.fromisoformat(iso)
    except ValueError:
        raise Exception(f"Invalid date: {value!r}, an epoch in seconds or an ISO 8601 date is expected")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def generate_identity_id(name: str, identity_class: str):
    """
    :param name:
    :param identity_class:
    :return:
    """
    data = {"name": name.lower().strip(), "identity_class": identity_class.lower()}
    data = canonicalize(data, utf8=False)
    entity_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "identity--" + entity_id

def generate_indicator_id(pattern: str):
    """Generate the OpenCTI standard id of an indicator from its STIX pattern.

    The id is derived from the pattern the same way OpenCTI does it, so the
    sighting is attached to the indicator already present on the platform
    instead of creating a duplicate one.

    :param pattern:
    :return:
    """
    data = {"pattern": pattern}
    data = canonicalize(data, utf8=False)
    entity_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "indicator--" + entity_id

def generate_incident_id(name: str, created):
    """
    :param name:
    :param created:
    :return:
    """
    if isinstance(created, datetime.datetime):
        created = created.isoformat()
    data = {"name": name.lower().strip(), "created": created}
    data = canonicalize(data, utf8=False)
    entity_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "incident--" + entity_id

def generate_sighting_id(
        sighting_of_ref,
        where_sighted_refs,
        first_seen=None,
        last_seen=None,
):
    """
    :param sighting_of_ref:
    :param where_sighted_refs:
    :param first_seen:
    :param last_seen:
    :return:
    """
    if isinstance(first_seen, datetime.datetime):
        first_seen = first_seen.isoformat()
    if isinstance(last_seen, datetime.datetime):
        last_seen = last_seen.isoformat()

    if first_seen is not None and last_seen is not None:
        data = {
            "type": "sighting",
            "sighting_of_ref": sighting_of_ref,
            "where_sighted_refs": where_sighted_refs,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }
    elif first_seen is not None:
        data = {
            "type": "sighting",
            "sighting_of_ref": sighting_of_ref,
            "where_sighted_refs": where_sighted_refs,
            "first_seen": first_seen,
        }
    else:
        data = {
            "type": "sighting",
            "sighting_of_ref": sighting_of_ref,
            "where_sighted_refs": where_sighted_refs,
        }
    data = canonicalize(data, utf8=False)
    entity_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "sighting--" + entity_id

def generate_case_incident_id(name: str, created):
    """
    :param name:
    :param created:
    :return:
    """
    name = name.lower().strip()
    if isinstance(created, datetime.datetime):
        created = created.isoformat()
    data = {"name": name, "created": created}
    data = canonicalize(data, utf8=False)
    entity_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "case-incident--" + entity_id

def generate_relation_id(
        relationship_type,
        source_ref,
        target_ref,
        start_time=None,
        stop_time=None
):
    """
    :param relationship_type:
    :param source_ref:
    :param target_ref:
    :param start_time:
    :param stop_time:
    :return:
    """
    if isinstance(start_time, datetime.datetime):
        start_time = start_time.isoformat()
    if isinstance(stop_time, datetime.datetime):
        stop_time = stop_time.isoformat()

    if start_time is not None and stop_time is not None:
        data = {
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "start_time": start_time,
            "stop_time": stop_time,
        }
    elif start_time is not None:
        data = {
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "start_time": start_time,
        }
    else:
        data = {
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
        }
    data = canonicalize(data, utf8=False)
    entity_id = str(uuid.uuid5(uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), data))
    return "relationship--" + entity_id
