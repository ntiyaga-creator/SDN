import json
import logging
from urllib.parse import urljoin

import requests

logger = logging.getLogger(__name__)


class RyuClient:
    def __init__(self, base_url="http://127.0.0.1:8081"):
        self.base_url = base_url
        self._connected = False

    def _request(self, method, path, data=None):
        url = urljoin(self.base_url, path)
        try:
            resp = requests.request(
                method, url,
                json=data,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            if resp.status_code in (200, 201, 204):
                return resp.json() if resp.text else {}
            logger.warning("Ryu API %s %s returned %s", method, path, resp.status_code)
            return None
        except requests.RequestException as e:
            logger.debug("Ryu connection failed: %s", e)
            return None

    def check_connection(self):
        result = self._request("GET", "/ryu/stats")
        self._connected = result is not None
        return self._connected

    @property
    def connected(self):
        return self._connected

    def get_stats(self):
        return self._request("GET", "/ryu/stats")

    def get_alerts(self):
        return self._request("GET", "/ryu/alerts")

    def clear_alerts(self):
        return self._request("POST", "/ryu/alerts/clear")

    def get_policies(self):
        return self._request("GET", "/ryu/policies")

    def add_policy(self, action, name="", description="", priority=100, enabled=True):
        return self._request("POST", "/ryu/policies", {
            "action": action, "name": name, "description": description,
            "priority": priority, "enabled": enabled
        })

    def toggle_policy(self, policy_id):
        return self._request("POST", f"/ryu/policies/{policy_id}/toggle")

    def delete_policy(self, policy_id):
        return self._request("DELETE", f"/ryu/policies/{policy_id}")

    def get_flows(self):
        return self._request("GET", "/ryu/flows")

    def get_topology(self):
        return self._request("GET", "/ryu/topology")

    def mitigate(self, alert_id):
        return self._request("POST", "/ryu/mitigate", {"alertId": alert_id})

    def update_settings(self, settings):
        return self._request("POST", "/ryu/settings", settings)

    def get_settings(self):
        return self._request("GET", "/ryu/settings")
