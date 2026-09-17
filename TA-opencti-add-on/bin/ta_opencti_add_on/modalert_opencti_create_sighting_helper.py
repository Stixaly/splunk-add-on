# encoding = utf-8
import json
from datetime import timedelta

from app_connector_helper import SplunkAppConnectorHelper
from stix_converter import convert_to_sighting, sighting_target_of
from constants import CONNECTOR_NAME, CONNECTOR_ID
from utils import parse_score, parse_days, event_field_values, unique


def refresh_sighted_indicator(helper, splunk_app_connector, bundle, params):
    """Apply the score and the validity asked by the alert to the sighted indicator.

    :param helper:
    :param splunk_app_connector:
    :param bundle: the sighting bundle that was sent
    :param params: the alert parameters
    :return:
    """
    score = parse_score(params.get("indicator_score"))
    validity_days = parse_days(params.get("indicator_validity_days"))
    if score is None and validity_days is None:
        return

    target = sighting_target_of(bundle)
    if target is None:
        helper.log_info("The sighting is attached to an observable, "
                        "there is no indicator to give a score or a validity to")
        return
    indicator_id, last_seen = target

    valid_until = None
    if validity_days is not None:
        valid_until = last_seen + timedelta(days=validity_days)

    try:
        splunk_app_connector.refresh_indicator(indicator_id, score=score, valid_until=valid_until)
    except Exception as ex:
        helper.log_error(f"Unable to update the sighted indicator {indicator_id}, "
                         f"exception: {str(ex)}")


def create_sighting(helper, event):
    """
    :param helper:
    :param event:
    :return:
    """
    if helper.get_param("labels"):
        labels = [x.strip() for x in helper.get_param("labels").split(',')]
    else:
        labels = []
    # remove potential empty labels
    labels = list(filter(None, labels))

    # the labels carried by a field of the result, by default the labels of
    # the indicator as opencti_lookup returns them, join the labels of the form
    labels_field = (helper.get_param("labels_field") or "").strip()
    if labels_field:
        labels = unique(labels + event_field_values(event, labels_field))

    helper.log_info(helper.get_param("sighting_of_value"))
    helper.log_info(type(helper.get_param("sighting_of_value")))
    helper.log_info(helper.get_param("sighting_of_type"))
    helper.log_info(type(helper.get_param("sighting_of_type")))
    helper.log_info(helper.get_param("where_sighted_value"))
    helper.log_info(type(helper.get_param("where_sighted_value")))
    helper.log_info(helper.get_param("where_sighted_type"))
    helper.log_info(type(helper.get_param("where_sighted_type")))
    helper.log_info(labels)
    helper.log_info(helper.get_param("tlp"))

    params = {
        "sighting_of_value": helper.get_param("sighting_of_value"),
        "sighting_of_type": helper.get_param("sighting_of_type"),
        "where_sighted_value": helper.get_param("where_sighted_value"),
        "where_sighted_type": helper.get_param("where_sighted_type"),
        # number of matches and the window they span when the alert
        # aggregates them, each empty for a plain single event sighting
        "count": helper.get_param("count"),
        "first_seen": helper.get_param("first_seen"),
        "last_seen": helper.get_param("last_seen"),
        # score and validity given to the sighted indicator, each empty to
        # leave the indicator as it is
        "indicator_score": helper.get_param("indicator_score"),
        "indicator_validity_days": helper.get_param("indicator_validity_days"),
        "labels_field": labels_field,
        "labels": labels,
        "tlp": helper.get_param("tlp"),
    }

    helper.log_info(f"Alert params={params}")

    opencti_url = helper.get_global_setting("opencti_url")
    opencti_api_key = helper.get_global_setting("opencti_api_key")

    splunk_app_connector = SplunkAppConnectorHelper(
        connector_id=CONNECTOR_ID,
        connector_name=CONNECTOR_NAME,
        opencti_url=opencti_url,
        opencti_api_key=opencti_api_key,
        splunk_helper=helper
    )

    # convert to_stix
    bundle = convert_to_sighting(
        alert_params=params,
        event=event
    )

    # going to register App as an OpenCTI connector
    # TODO: Do this only on time (at first run)
    try:
        splunk_app_connector.register()
    except Exception as ex:
        helper.log_error(f"Unable to create incident response case, "
                         f"an exception occurred while registering App as OpenCTI connector, "
                         f"exception: {str(ex)}")
        return

    try:
        splunk_app_connector.send_stix_bundle(bundle=bundle)
        helper.log_info("STIX bundle has been sent successfully")
    except Exception as ex:
        helper.log_error(f"Unable to create incident response case, "
                         f"an exception occurred while sending STIX bundle,"
                         f"exception: {str(ex)}")
        return

    refresh_sighted_indicator(helper, splunk_app_connector, bundle, params)


def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets the alert action parameters and prints them to the log
    labels = helper.get_param("labels")
    helper.log_info("labels={}".format(labels))

    tlp = helper.get_param("tlp")
    helper.log_info("tlp={}".format(tlp))

    observables_extraction = helper.get_param("observables_extraction")
    helper.log_info("observables_extraction={}".format(observables_extraction))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    # Set the current LOG level
    helper.set_log_level(helper.log_level)

    helper.log_info("Alert action create_sighting started.")

    events = helper.get_events()
    for event in events:
        helper.log_debug("event={}".format(json.dumps(event)))
        create_sighting(helper, event)

    return 0
