"""Alert collection. Wazuh stores alerts in the Wazuh Indexer (index wazuh-alerts-*),
NOT in the manager REST API, so we query the indexer (port 9200) with the scroll API."""
import json
import requests
import urllib3
from . import config

if not config.VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_alerts(hours=24, min_level=0, page=1000, max_docs=500_000):
    auth = (config.INDEXER_USER, config.INDEXER_PASS)
    body = {
        "size": page,
        "sort": [{"timestamp": "asc"}],
        "query": {"bool": {"filter": [
            {"range": {"timestamp": {"gte": f"now-{int(hours * 60)}m"}}},
            {"range": {"rule.level": {"gte": min_level}}},
        ]}},
    }
    r = requests.post(f"{config.INDEXER_URL}/wazuh-alerts-*/_search?scroll=2m",
                      json=body, auth=auth, verify=config.VERIFY_TLS, timeout=60)
    r.raise_for_status()
    data, out = r.json(), []
    while data["hits"]["hits"] and len(out) < max_docs:
        out.extend(h["_source"] for h in data["hits"]["hits"])
        r = requests.post(f"{config.INDEXER_URL}/_search/scroll",
                          json={"scroll": "2m", "scroll_id": data["_scroll_id"]},
                          auth=auth, verify=config.VERIFY_TLS, timeout=60)
        r.raise_for_status()
        data = r.json()
    return out


def load_alerts_file(path):
    """Offline mode: read a Wazuh alerts.json file (one JSON per line),
    e.g. copied from /var/ossec/logs/alerts/alerts.json in the manager container."""
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
