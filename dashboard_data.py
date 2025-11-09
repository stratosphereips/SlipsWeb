import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple

import requests
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config" / "medallion_config.json"
DEFAULT_COLLECTION_TITLE = "Alerts"
DISCOVERY_PATH = "/taxii2/"
ALERTS_API_PATH = "/alerts/"
ACCEPT_HEADER = "application/taxii+json;version=2.1"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {sev: (len(SEVERITY_ORDER) - idx) for idx, sev in enumerate(SEVERITY_ORDER)}


def _load_medallion_config() -> Tuple[str, Tuple[str, str]]:
    with CONFIG_PATH.open() as config_file:
        config = json.load(config_file)

    host = config["server"].get("host", "127.0.0.1")
    port = config["server"].get("port", 1234)
    base_url = f"http://{host}:{port}".rstrip("/")

    users = config.get("users", {})
    if not users:
        raise RuntimeError("No TAXII users defined in medallion_config.json")

    username, password = next(iter(users.items()))
    max_page_size = config.get("taxii", {}).get("max_page_size", 100)
    return base_url, (username, password), max_page_size


def _discover_api_root(base_url: str, auth: Tuple[str, str]) -> str:
    discovery_url = f"{base_url}{DISCOVERY_PATH}"
    response = requests.get(
        discovery_url,
        headers={"Accept": ACCEPT_HEADER},
        auth=auth,
        timeout=10,
    )
    response.raise_for_status()
    api_roots = response.json().get("api_roots", [])

    if not api_roots:
        raise RuntimeError("No API roots advertised by TAXII discovery endpoint")

    for root in api_roots:
        if root.rstrip("/").endswith(ALERTS_API_PATH.rstrip("/")):
            return root.rstrip("/") + "/"

    return api_roots[0].rstrip("/") + "/"


def _select_collection(api_root: str, auth: Tuple[str, str]) -> Dict:
    response = requests.get(
        f"{api_root}collections/",
        headers={"Accept": ACCEPT_HEADER},
        auth=auth,
        timeout=10,
    )
    response.raise_for_status()
    collections = response.json().get("collections", [])
    if not collections:
        raise RuntimeError("No collections available on TAXII server")

    for collection in collections:
        title = collection.get("title", "").lower()
        if DEFAULT_COLLECTION_TITLE.lower() in title:
            return collection
    return collections[0]


def _build_page_url(base_url: str, limit: int, next_token: str = None) -> str:
    parsed = urlparse(base_url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    params["limit"] = str(limit)
    if next_token:
        params["next"] = next_token
    else:
        params.pop("next", None)
    new_query = urlencode(params)
    return urlunparse(parsed._replace(query=new_query))


def _fetch_objects(
    collection_info: Dict, auth: Tuple[str, str], max_page_size: int
) -> List[Dict]:
    objects_url = collection_info["objects"] if "objects" in collection_info else None
    if not objects_url:
        objects_url = f"{collection_info['url']}objects/" if collection_info.get("url") else None
    if not objects_url:
        collection_id = collection_info.get("id")
        api_root = collection_info.get("api_root")
        if api_root and collection_id:
            objects_url = f"{api_root}collections/{collection_id}/objects/"

    if not objects_url:
        raise RuntimeError("Unable to determine objects URL for the TAXII collection")

    headers = {"Accept": ACCEPT_HEADER}
    collected: List[Dict] = []
    page_url = _build_page_url(objects_url, max_page_size)
    safety = 0
    while page_url and safety < 1000:
        response = requests.get(page_url, headers=headers, auth=auth, timeout=10)
        response.raise_for_status()
        payload = response.json()
        collected.extend(payload.get("objects", []))
        next_token = payload.get("next")
        if next_token:
            page_url = _build_page_url(objects_url, max_page_size, next_token)
        else:
            page_url = None
        safety += 1
    return collected


def _severity_rank(level: str) -> int:
    if not level:
        return 0
    return SEVERITY_RANK.get(level.lower(), 0)


def _normalize_severity(indicator: Dict) -> str:
    level = indicator.get("x_slips_threat_level")
    if level:
        return str(level).lower()
    labels = indicator.get("labels") or []
    for label in labels:
        lower = label.lower()
        if lower in SEVERITY_ORDER:
            return lower
    return "info"


def _parse_when(indicator: Dict) -> datetime:
    ts = indicator.get("valid_from") or indicator.get("created")
    if not ts:
        return datetime.utcnow().replace(tzinfo=timezone.utc)
    try:
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
    except ValueError:
        dt = datetime.utcnow().replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _build_timeline(evidences: List[Dict]) -> List[Dict]:
    bucket = Counter()
    for evidence in evidences:
        dt = _parse_when(evidence)
        minute = dt.replace(second=0, microsecond=0).isoformat()
        bucket[minute] += 1
    return [
        {"timestamp": ts, "count": bucket[ts]}
        for ts in sorted(bucket.keys())
    ]


def _summarize_ips(evidences: List[Dict]) -> List[Dict]:
    summary: Dict[str, Dict] = {}
    for evidence in evidences:
        ip = evidence.get("x_slips_profile_ip")
        if not ip:
            continue
        direction = evidence.get("x_slips_attacker_direction")
        victim = evidence.get("x_slips_victim")
        severity = _normalize_severity(evidence)
        rank = _severity_rank(severity)

        if ip not in summary:
            summary[ip] = {
                "ip": ip,
                "count": 0,
                "direction": direction,
                "victim": victim,
                "top_severity": severity,
                "top_rank": rank,
            }
        entry = summary[ip]
        entry["count"] += 1
        entry["direction"] = direction or entry["direction"]
        entry["victim"] = victim or entry["victim"]
        if rank > entry.get("top_rank", -1):
            entry["top_severity"] = severity
            entry["top_rank"] = rank

    return sorted(
        summary.values(),
        key=lambda item: (item.get("top_rank", 0), item["count"]),
        reverse=True,
    )


def _prepare_evidences(objects: List[Dict]) -> List[Dict]:
    evidences = []
    for indicator in objects:
        if indicator.get("type") != "indicator":
            continue
        severity = _normalize_severity(indicator)
        dt_obj = _parse_when(indicator)
        timestamp_raw = indicator.get("valid_from") or indicator.get("created") or dt_obj.isoformat()

        evidences.append(
            {
                "id": indicator.get("x_slips_evidence_id") or indicator.get("id"),
                "stix_id": indicator.get("id"),
                "name": indicator.get("name"),
                "description": indicator.get("description"),
                "pattern": indicator.get("pattern"),
                "timestamp": timestamp_raw,
                "sort_ts": dt_obj.isoformat(),
                "severity": severity,
                "severity_rank": _severity_rank(severity),
                "profile_ip": indicator.get("x_slips_profile_ip"),
                "direction": indicator.get("x_slips_attacker_direction"),
                "victim": indicator.get("x_slips_victim"),
                "flow_uids": indicator.get("x_slips_flow_uids", []),
                "dst_port": indicator.get("x_slips_dst_port"),
                "src_port": indicator.get("x_slips_src_port"),
                "labels": indicator.get("labels", []),
            }
        )
    return sorted(
        evidences,
        key=lambda ev: (
            ev["severity_rank"],
            ev.get("sort_ts"),
        ),
        reverse=True,
    )


def get_dashboard_payload() -> Dict:
    try:
        base_url, auth, page_size = _load_medallion_config()
        api_root = _discover_api_root(base_url, auth)
        collection = _select_collection(api_root, auth)
        collection.setdefault("api_root", api_root)
        collection.setdefault("url", f"{api_root}collections/{collection.get('id')}/")
        objects = _fetch_objects(collection, auth, page_size)

        evidences = _prepare_evidences(objects)
        timeline = _build_timeline(evidences)
        ip_summary = _summarize_ips(evidences)
        summary = {
            "total_evidences": len(evidences),
            "unique_ips": len(ip_summary),
            "critical": sum(1 for e in evidences if e["severity"] == "critical"),
            "high": sum(1 for e in evidences if e["severity"] == "high"),
            "collection": collection.get("title") or collection.get("id"),
        }

        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "timeline": timeline,
            "ip_summary": ip_summary,
            "evidences": evidences,
            "summary": summary,
            "severity_order": SEVERITY_ORDER,
        }
    except Exception as exc:  # pragma: no cover - defensive path
        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "timeline": [],
            "ip_summary": [],
            "evidences": [],
            "summary": {
                "total_evidences": 0,
                "unique_ips": 0,
                "critical": 0,
                "high": 0,
                "collection": "Unavailable",
            },
            "severity_order": SEVERITY_ORDER,
            "error": str(exc),
        }
