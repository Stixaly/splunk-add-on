import stix2
from datetime import datetime, timezone

from stix_constants import CustomObservableUserAgent, CustomObservableText, CustomObjectCaseIncident
from stix_constants import CustomObservableHostname
from utils import get_hash_type, is_ipv6, is_ipv4
from utils import generate_incident_id, generate_identity_id, generate_relation_id, generate_case_incident_id, generate_sighting_id
from utils import generate_indicator_id
from utils import parse_count, parse_timestamp

FAKE_INDICATOR_ID = "indicator--51b92778-cef0-4a90-b7ec-ebd620d01ac8"

# STIX pattern of each observable type an indicator can be built from
STIX_PATTERNS = {
    "ipv4": "[ipv4-addr:value = '{value}']",
    "ipv6": "[ipv6-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "hostname": "[hostname:value = '{value}']",
    "email_addr": "[email-addr:value = '{value}']",
    "user_agent": "[user-agent:value = '{value}']",
    "file_name": "[file:name = '{value}']",
    "md5": "[file:hashes.'MD5' = '{value}']",
    "sha1": "[file:hashes.'SHA-1' = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
    "sha512": "[file:hashes.'SHA-512' = '{value}']",
}


def _build_stix_pattern(observable_type, value):
    """Build the STIX pattern of an indicator out of an observable type/value

    :param observable_type:
    :param value:
    :return:
    """
    if observable_type not in STIX_PATTERNS:
        raise Exception(f"Unable to build a STIX pattern for type: {observable_type}")
    # escape the characters that would otherwise break the pattern
    escaped_value = str(value).replace("\\", "\\\\").replace("'", "\\'")
    return STIX_PATTERNS[observable_type].format(value=escaped_value)


def _get_stix_marking_id(value):
    if value == "tlp_clear":
        return stix2.TLP_WHITE
    if value == "tlp_green":
        return stix2.TLP_GREEN
    if value == "tlp_amber":
        return stix2.TLP_AMBER
    if value == "tlp_red":
        return stix2.TLP_RED



def _extract_observables_from_cim_model(event, marking, creator):
    """
    :param event:
    :param marking:
    :param creator:
    :return:
    """
    observables = []
    if "url" in event and event.get("url") != "":
        observables.append({"type": "url", "value": event.get("url")})
    if "url_domain" in event and event.get("url_domain") != "":
        observables.append({"type": "domain", "value": event.get("url_domain")})
    if "user" in event and event.get("user") != "unknown" and event.get("user") != "":
        observables.append({"type": "user_account", "value": event.get("user")})
    if "user_name" in event and event.get("user_name") != "unknown" and event.get("user_name") != "":
        observables.append({"type": "user_account", "value": event.get("user_name")})
    if "user_agent" in event and event.get("user_agent") != "":
        observables.append({"type": "user_agent", "value": event.get("http_user_agent")})
    if "http_user_agent" in event and event.get("http_user_agent") != "":
        observables.append({"type": "user_agent", "value": event.get("http_user_agent")})
    if "dest" in event and event.get("dest") != "":
        if is_ipv4(event.get("dest")):
            observables.append({"type": "ipv4", "value": event.get("dest")})
        elif is_ipv6(event.get("dest")):
            observables.append({"type": "ipv6", "value": event.get("dest")})
        else:
            observables.append({"type": "hostname", "value": event.get("dest")})
    if "dest_ip" in event and event.get("dest_ip") != "":
        if is_ipv4(event.get("dest_ip")):
            observables.append({"type": "ipv4", "value": event.get("dest_ip")})
        if is_ipv6(event.get("dest_ip")):
            observables.append({"type": "ipv6", "value": event.get("dest_ip")})
    if "src" in event and event.get("src") != "":
        if is_ipv4(event.get("src")):
            observables.append({"type": "ipv4", "value": event.get("src")})
        elif is_ipv6(event.get("src")):
            observables.append({"type": "ipv6", "value": event.get("src")})
        else:
            observables.append({"type": "hostname", "value": event.get("src")})
    if "src_ip" in event and event.get("src_ip") != "":
        if is_ipv4(event.get("src_ip")):
            observables.append({"type": "ipv4", "value": event.get("src_ip")})
        if is_ipv6(event.get("src_ip")):
            observables.append({"type": "ipv6", "value": event.get("src_ip")})
    if "file_hash" in event and event.get("file_hash") != "":
        # the algorithm has to be resolved from the value, "hash" alone is not
        # a type this converter knows and the observable would be dropped
        hash_type = get_hash_type(event.get("file_hash"))
        if hash_type:
            observables.append({"type": hash_type, "value": event.get("file_hash")})
    if "file_name" in event and event.get("file_name") != "":
        observables.append({"type": "file_name", "value": event.get("file_name")})

    return _convert_observables_to_stix(observables, marking, creator)


def _extract_observables_from_key_model(event, marking, creator):
    """
    :param event:
    :param marking:
    :param creator:
    :return:
    """
    observables = []
    prefix = "octi"
    # print the keys and values
    for field in event:
        if field.startswith(prefix):
            for key in ["ip", "url", "domain", "hash", "email_addr",
                        "user_agent", "mutex", "text", "windows_registry_key",
                        "windows_registry_value_type", "directory", "email_message",
                        "file_name", "mac_addr", "user_account"]:
                if field == prefix + "_" + key:
                    if key == "hash":
                        hash_type = get_hash_type(event[field])
                        if hash_type:
                            observables.append({"type": hash_type, "value": event[field]})
                    if key == "ip":
                        ipv4 = is_ipv4(event[field])
                        if ipv4:
                            observables.append({"type": "ipv4", "value": event[field]})
                        ipv6 = is_ipv6(event[field])
                        if ipv6:
                            observables.append({"type": "ipv6", "value": event[field]})
                    else:
                        observables.append({"type": key, "value": event[field]})
    return _convert_observables_to_stix(observables, marking, creator)


def _convert_observables_to_stix(observables, marking, creator):
    """
    :param observables:
    :param marking:
    :param creator:
    :return:
    """
    stix_observables = []
    customer_properties = {
        "created_by_ref": creator["id"]
    }

    for observable in observables:
        if observable.get("type") == "ipv4":
            stix_observable = stix2.IPv4Address(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "ipv6":
            stix_observable = stix2.IPv6Address(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "url":
            stix_observable = stix2.URL(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "domain":
            stix_observable = stix2.DomainName(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "hostname":
            stix_observable = CustomObservableHostname(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "md5":
            stix_observable = stix2.File(
                name=observable.get("value"),
                hashes={"MD5": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "sha1":
            stix_observable = stix2.File(
                name=observable.get("value"),
                hashes={"SHA-1": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "sha256":
            stix_observable = stix2.File(
                name=observable.get("value"),
                hashes={"SHA-256": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "sha512":
            stix_observable = stix2.File(
                name=observable.get("value"),
                hashes={"SHA-512": observable.get("value")},
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "file_name":
            stix_observable = stix2.File(
                name=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "email_addr":
            stix_observable = stix2.EmailAddress(
                type="email-addr",
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "user_agent":
            stix_observable = CustomObservableUserAgent(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "mutex":
            stix_observable = stix2.Mutex(
                type="mutex",
                name=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "text":
            stix_observable = CustomObservableText(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "windows_registry_key":
            stix_observable = stix2.WindowsRegistryKey(
                key=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "windows_registry_value_type":
            stix_observable = stix2.WindowsRegistryValueType(
                data=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "directory":
            stix_observable = stix2.Directory(
                path=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "email_message":
            stix_observable = stix2.EmailMessage(
                subject=observable.get("value"),
                is_multipart=False,
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "mac_addr":
            stix_observable = stix2.MACAddress(
                value=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
        if observable.get("type") == "user_account":
            stix_observable = stix2.UserAccount(
                account_login=observable.get("value"),
                display_name=observable.get("value"),
                object_marking_refs=[marking],
                custom_properties=customer_properties
            )
            stix_observables.append(stix_observable)
    return stix_observables


def convert_to_incident_response(alert_params, event):
    """
    :param alert_params:
    :param event:
    :return:
    """
    bundle_objects = []

    # event date
    if "_time" in event and event.get("_time"):
        event_date = datetime.fromtimestamp(float(event.get("_time")), timezone.utc)
    else:
        event_date = datetime.now(timezone.utc)

    # manage marking
    marking = alert_params.get("tlp")
    marking_id = _get_stix_marking_id(marking)

    # manage author
    stix_author = stix2.Identity(
        id=generate_identity_id(event.get("host", "Splunk"), "system"),
        name=event.get("host", "Splunk"),
        identity_class="system"
    )
    bundle_objects.append(stix_author)

    # observables extraction
    observable_ref_ids = []
    if alert_params.get("observables_extraction") == "cim_model":
        observables = _extract_observables_from_cim_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)
    if alert_params.get("observables_extraction") == "field_mapping":
        observables = _extract_observables_from_key_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)

    # create incident response case
    stix_case_incident = CustomObjectCaseIncident(
        id=generate_case_incident_id(alert_params.get("name"), event_date),
        name=alert_params.get("name"),
        description=alert_params.get("description"),
        severity=alert_params.get("severity"),
        priority=alert_params.get("priority"),
        labels=alert_params.get("labels"),
        created=event_date,
        external_references=[],
        created_by_ref=stix_author.id,
        object_marking_refs=[marking_id],
        object_refs=observable_ref_ids
    )
    bundle_objects.append(stix_case_incident)

    bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
    return bundle.serialize()


def convert_to_incident(alert_params, event):
    """
    :param alert_params:
    :param event:
    :return:
    """
    bundle_objects = []

    # event date
    if "_time" in event and event.get("_time"):
        event_date = datetime.fromtimestamp(float(event.get("_time")), timezone.utc)
    else:
        event_date = datetime.now(timezone.utc)

    # manage marking
    marking = alert_params.get("tlp", "tlp_clear")
    marking_id = _get_stix_marking_id(marking)

    # manage author
    stix_author = stix2.Identity(
        id=generate_identity_id(event.get("host", "Splunk"), "system"),
        name=event.get("host", "Splunk"),
        identity_class="system"
    )
    bundle_objects.append(stix_author)

    # observables extraction
    observable_ref_ids = []
    if alert_params.get("observables_extraction") == "cim_model":
        observables = _extract_observables_from_cim_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)
    if alert_params.get("observables_extraction") == "field_mapping":
        observables = _extract_observables_from_key_model(
            event=event,
            marking=marking_id,
            creator=stix_author
        )
        for observable in observables:
            bundle_objects.append(observable)
            observable_ref_ids.append(observable.id)

    # create incident
    stix_incident = stix2.Incident(
        id=generate_incident_id(alert_params.get("name"), event_date),
        name=alert_params.get("name"),
        created=event_date,
        description=alert_params.get("description"),
        object_marking_refs=[marking_id],
        created_by_ref=stix_author.id,
        external_references=[],
        labels=alert_params.get("labels"),
        allow_custom=True,
        custom_properties={
            "source": event.get("host", "Splunk"),
            "severity": alert_params.get("severity"),
            "incident_type": alert_params.get("type"),
            "first_seen": event_date
        }
    )
    bundle_objects.append(stix_incident)

    for observable_id in observable_ref_ids:
        stix_relation_account = stix2.Relationship(
            id=generate_relation_id(
                "related-to", observable_id, stix_incident.id),
            relationship_type="related-to",
            source_ref=observable_id,
            target_ref=stix_incident.id,
            created_by_ref=stix_author.id)
        bundle_objects.append(stix_relation_account)

    bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
    return bundle.serialize()

def convert_to_sighting(alert_params, event):
    """
    :param alert_params:
    :param event:
    :return:
    """
    bundle_objects = []

    # event date
    if "_time" in event and event.get("_time"):
        event_date = datetime.fromtimestamp(float(event.get("_time")), timezone.utc)
    else:
        event_date = datetime.now(timezone.utc)

    # when the alert aggregates the matches of an indicator, the number of
    # them and the window they span are given by the alert parameters. Each
    # falls back to the single event otherwise, and a window with only one of
    # its ends is read as that instant
    count = parse_count(alert_params.get("count"))
    first_seen = parse_timestamp(alert_params.get("first_seen"))
    last_seen = parse_timestamp(alert_params.get("last_seen"))
    if first_seen is None and last_seen is None:
        first_seen = last_seen = event_date
    elif first_seen is None:
        first_seen = last_seen
    elif last_seen is None:
        last_seen = first_seen
    if last_seen < first_seen:
        raise Exception(f"Invalid sighting dates: first_seen {first_seen.isoformat()} "
                        f"is later than last_seen {last_seen.isoformat()}")

    # manage marking
    marking = alert_params.get("tlp")
    marking_id = _get_stix_marking_id(marking)

    # manage author
    stix_author = stix2.Identity(
        id=generate_identity_id(event.get("host", "Splunk"), "system"),
        name=event.get("host", "Splunk"),
        identity_class="system"
    )
    bundle_objects.append(stix_author)

    sighting_of_value=alert_params.get("sighting_of_value")
    sighting_of_type=alert_params.get("sighting_of_type")
    where_sighted_value=alert_params.get("where_sighted_value")
    where_sighted_type=alert_params.get("where_sighted_type")

    if where_sighted_type.lower() == "organization":
        where_sighted = stix2.Identity(
            id=generate_identity_id(str(where_sighted_value), "organization"),
            name=str(where_sighted_value),
            identity_class="organization"
        )
    elif where_sighted_type.lower() == "system":
        where_sighted = stix2.Identity(
            id=generate_identity_id(str(where_sighted_value), "system"),
            name=str(where_sighted_value),
            identity_class="system"
        )
    else:
        raise Exception(f"Invalid where_sighted_type: {where_sighted_type}")

    bundle_objects.append(where_sighted)

    # sighting_of conversion
    # the sighting is attached either to an indicator or to an observable,
    # depending on the type selected in the alert action
    custom_properties = {}

    if sighting_of_type == "indicator" or sighting_of_type.endswith("_indicator"):
        observable_type = sighting_of_type.split("_indicator")[0]

        if sighting_of_type == "indicator" and str(sighting_of_value).startswith("indicator--"):
            # the indicator standard id comes straight from the OpenCTI lookup,
            # the indicator already exists on the platform so it is only referenced
            sighting_of_ref = str(sighting_of_value)
        else:
            if sighting_of_type == "indicator":
                # the value is expected to be a STIX pattern
                pattern = str(sighting_of_value)
            else:
                pattern = _build_stix_pattern(observable_type, sighting_of_value)

            # the id is computed the OpenCTI way so that the sighting is attached
            # to the existing indicator instead of creating a duplicate one
            sighting_of_ref = generate_indicator_id(pattern)
            stix_indicator = stix2.Indicator(
                id=sighting_of_ref,
                name=str(sighting_of_value),
                pattern=pattern,
                pattern_type="stix",
                valid_from=event_date,
                created_by_ref=stix_author.id,
                object_marking_refs=[marking_id],
                labels=alert_params.get("labels"),
                allow_custom=True,
            )
            bundle_objects.append(stix_indicator)

            # keep the observable in the bundle and link it to the indicator
            if observable_type in STIX_PATTERNS:
                stix_observables = _convert_observables_to_stix(
                    observables=[{"type": observable_type, "value": sighting_of_value}],
                    marking=marking_id,
                    creator=stix_author
                )
                if stix_observables:
                    stix_observable = stix_observables[0]
                    bundle_objects.append(stix_observable)
                    bundle_objects.append(stix2.Relationship(
                        id=generate_relation_id(
                            "based-on", sighting_of_ref, stix_observable["id"]),
                        relationship_type="based-on",
                        source_ref=sighting_of_ref,
                        target_ref=stix_observable["id"],
                        created_by_ref=stix_author.id
                    ))

    elif "_observable" in sighting_of_type:
        obs = {
            "type": sighting_of_type.split("_observable")[0],
            "value": sighting_of_value
        }

        stix_observables = _convert_observables_to_stix(
            observables=[obs],
            marking=marking_id,
            creator=stix_author
        )
        if not stix_observables:
            raise Exception(f"Unsupported sighting_of_type: {sighting_of_type}")
        stix_observable = stix_observables[0]
        bundle_objects.append(stix_observable)

        # OpenCTI resolves the sighting target through x_opencti_sighting_of_ref,
        # sighting_of_ref only carries a placeholder indicator
        sighting_of_ref = FAKE_INDICATOR_ID
        custom_properties["x_opencti_sighting_of_ref"] = stix_observable["id"]

    else:
        raise Exception(f"Invalid sighting_of_type: {sighting_of_type}")

    sighting = stix2.Sighting(
        id=generate_sighting_id(
            custom_properties.get("x_opencti_sighting_of_ref", sighting_of_ref),
            where_sighted["id"],
            #event_date,
            #event_date,
        ),
        created_by_ref=stix_author.id,
        description=None,
        sighting_of_ref=sighting_of_ref,
        first_seen=first_seen,
        last_seen=last_seen,
        where_sighted_refs=[where_sighted],
        count=count,
        object_marking_refs=[marking_id],
        labels=alert_params.get("labels"),
        custom_properties=custom_properties,
    )

    bundle_objects.append(sighting)

    bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True)
    return bundle.serialize()
