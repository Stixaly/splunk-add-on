import requests
from datetime import timezone

from utils import get_proxy_config, parse_timestamp
from constants import VERIFY_SSL

# fields read back from an indicator, enough to decide what a refresh changes
INDICATOR_FIELDS = "id standard_id x_opencti_score valid_until revoked"

class SplunkAppConnectorHelper:
    def __init__(
            self,
            connector_id,
            connector_name,
            opencti_url,
            opencti_api_key,
            splunk_helper
    ):
        self.connector_id = connector_id
        self.connector_name = connector_name
        self.opencti_url = opencti_url
        self.splunk_helper = splunk_helper
        self.headers = {
            "Authorization": "Bearer " + opencti_api_key,
        }
        self.api_url = self.opencti_url + "/graphql"

        # manage SSL verification
        splunk_helper.log_debug(f"verify SSL: {VERIFY_SSL}")

        # manage proxies configuration
        self.proxies = get_proxy_config(splunk_helper)

    def register(self):
        """
        :return:
        """
        input = {
            "input": {
                "id": self.connector_id,
                "name": self.connector_name,
                "type": "STREAM",
                "scope": "",
                "auto": False,
                "only_contextual": False,
                "playbook_compatible": False,
            }
        }

        query = """
            mutation RegisterConnector($input: RegisterConnectorInput) {
                registerConnector(input: $input) {
                    id
                    connector_state
                    config {
                        connection {
                            host
                            vhost
                            use_ssl
                            port
                            user
                            pass
                        }
                        listen
                        listen_routing
                        listen_exchange
                        push
                        push_routing
                        push_exchange
                    }
                    connector_user_id
                }
            }
        """

        return self._graphql(query, input).get("registerConnector")

    def send_stix_bundle(self, bundle):
        """
        :param bundle:
        :return:
        """
        query = """
            mutation stixBundle($id: String!, $bundle: String!) {
                stixBundlePush(connectorId: $id, bundle: $bundle)
            }
        """

        variables = {
            "id": self.connector_id,
            "bundle": bundle
        }

        # the mutation answers true once the bundle is queued for ingestion
        if not self._graphql(query, variables).get("stixBundlePush"):
            raise Exception("OpenCTI did not accept the STIX bundle")

    def _graphql(self, query, variables):
        """Run a GraphQL operation and return its data.

        A functional error is returned by OpenCTI with a 200 status and an
        "errors" list, it is raised here like a transport error.

        :param query:
        :param variables:
        :return:
        """
        r = requests.post(
            url=self.api_url,
            json={"query": query, "variables": variables},
            headers=self.headers,
            verify=VERIFY_SSL,
            proxies=self.proxies
        )
        if r.status_code != 200:
            raise Exception(f"An exception occurred while querying OpenCTI, "
                            f"received status code: {r.status_code}, exception: {r.content}")
        try:
            payload = r.json()
        except ValueError:
            raise Exception(f"OpenCTI answered with something that is not JSON, "
                            f"is the URL that of the platform? Answer: {r.content[:200]}")
        if not isinstance(payload, dict):
            raise Exception(f"OpenCTI answered with something that is not a GraphQL response: {payload!r}"[:400])
        errors = payload.get("errors")
        if errors:
            messages = "; ".join(str(error.get("message", error)) for error in errors)
            raise Exception(f"OpenCTI returned an error: {messages}")
        return payload.get("data") or {}

    def read_indicator(self, indicator_id):
        """
        :param indicator_id: OpenCTI id or STIX id of the indicator
        :return: the indicator, or None when it is not on the platform
        """
        query = """
            query ReadIndicator($id: String!) {
                indicator(id: $id) { %s }
            }
        """ % INDICATOR_FIELDS
        return self._graphql(query, {"id": indicator_id}).get("indicator")

    def patch_indicator(self, indicator_id, key, value):
        """
        :param indicator_id:
        :param key: the attribute to set
        :param value: its new value
        :return: the indicator as OpenCTI holds it after the update
        """
        query = """
            mutation PatchIndicator($id: ID!, $input: [EditInput!]!) {
                indicatorFieldPatch(id: $id, input: $input) { %s }
            }
        """ % INDICATOR_FIELDS
        variables = {"id": indicator_id, "input": [{"key": key, "value": [value]}]}
        return self._graphql(query, variables).get("indicatorFieldPatch")

    def refresh_indicator(self, indicator_id, score=None, valid_until=None):
        """Give a sighted indicator a new score and a longer validity.

        The score is sent on its own: OpenCTI drops the score of an update that
        carries valid_until too, and a score change restarts the decay of the
        indicator. valid_until is only ever moved later, a sighting must not
        shorten the life of an indicator.

        :param indicator_id: OpenCTI id or STIX id of the indicator
        :param score: new score, or None to leave it unchanged
        :param valid_until: aware datetime, or None to leave it unchanged
        :return: the indicator as OpenCTI holds it, or None when it is not on
                 the platform
        """
        log = self.splunk_helper
        indicator = self.read_indicator(indicator_id)
        if indicator is None:
            log.log_info(f"Indicator {indicator_id} is not on OpenCTI yet, "
                         f"its score and validity come from the bundle")
            return None
        if score is not None:
            indicator = self.patch_indicator(indicator_id, "x_opencti_score", score) or indicator
            log.log_info(f"Indicator {indicator_id} given the score {score}, "
                         f"OpenCTI now holds {indicator.get('x_opencti_score')}")
        if valid_until is not None:
            current = parse_timestamp(indicator.get("valid_until"))
            if current is None or current < valid_until:
                value = valid_until.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                indicator = self.patch_indicator(indicator_id, "valid_until", value) or indicator
                log.log_info(f"Indicator {indicator_id} valid until {indicator.get('valid_until')}")
            else:
                log.log_info(f"Indicator {indicator_id} already valid until {indicator.get('valid_until')}, "
                             f"later than {valid_until.isoformat()}, left unchanged")
        return indicator
