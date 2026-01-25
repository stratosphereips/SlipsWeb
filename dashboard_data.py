import json
import os
import threading
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
TAXII1_HEADERS = {
    "Content-Type": "application/xml",
    "Accept": "application/xml",
    "X-TAXII-Content-Type": "urn:taxii.mitre.org:message:xml:1.1",
    "X-TAXII-Accept": "urn:taxii.mitre.org:message:xml:1.1",
    "X-TAXII-Protocol": "urn:taxii.mitre.org:protocol:http:1.0",
    "X-TAXII-Services": "urn:taxii.mitre.org:services:1.1",
}
TAXII1_NS = {
    "taxii_11": "http://taxii.mitre.org/messages/taxii_xml_binding-1.1",
    "stix": "http://stix.mitre.org/stix-1",
    "indicator": "http://stix.mitre.org/Indicator-2",
    "cybox": "http://cybox.mitre.org/cybox-2",
    "AddressObj": "http://cybox.mitre.org/objects#AddressObject-2",
    "DomainNameObj": "http://cybox.mitre.org/objects#DomainNameObject-1",
    "URIObj": "http://cybox.mitre.org/objects#URIObject-2",
    "stixCommon": "http://stix.mitre.org/common-1",
}
TAXII1_CACHE_MAX = int(os.getenv("TAXII1_CACHE_MAX", "5000"))
TAXII1_LOOKBACK_HOURS = int(os.getenv("TAXII1_LOOKBACK_HOURS", "24"))

_TAXII1_LOCK = threading.Lock()
_TAXII1_CACHE = {
    "items": [],
    "ids": set(),
    "last_poll": None,
    "last_poll_ts": 0.0,
}


def _load_medallion_config() -> Tuple[str, Tuple[str, str], int]:
    config = {}
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open() as config_file:
            config = json.load(config_file)

    def _env_int(name: str, default: int) -> int:
        value = os.getenv(name)
        if value is None:
            return default
        try:
            return int(value)
        except ValueError:
            return default

    env_base_url = os.getenv("TAXII_BASE_URL")
    env_host = os.getenv("TAXII_HOST")
    env_port = os.getenv("TAXII_PORT")
    env_scheme = os.getenv("TAXII_SCHEME", "http")

    base_url = None
    if env_base_url:
        base_url = env_base_url.rstrip("/")
    elif env_host or env_port:
        host = env_host or "127.0.0.1"
        port = env_port or "1234"
        base_url = f"{env_scheme}://{host}:{port}".rstrip("/")
    else:
        backend = os.getenv("TAXII_BACKEND", "").lower()
        if backend == "opentaxii":
            base_url = "http://opentaxii:9000"
        elif backend == "medallion":
            base_url = "http://medallion:1234"

    if not base_url:
        host = config.get("server", {}).get("host", "127.0.0.1")
        port = config.get("server", {}).get("port", 1234)
        base_url = f"http://{host}:{port}".rstrip("/")

    env_user = os.getenv("TAXII_USERNAME") or os.getenv("MEDALLION_USERNAME")
    env_password = os.getenv("TAXII_PASSWORD") or os.getenv("MEDALLION_PASSWORD")
    if env_user and env_password:
        auth = (env_user, env_password)
    else:
        users = config.get("users", {})
        if not users:
            raise RuntimeError("No TAXII users defined in medallion_config.json")
        auth = next(iter(users.items()))

    max_page_size = _env_int(
        "TAXII_MAX_PAGE_SIZE",
        config.get("taxii", {}).get("max_page_size", 100),
    )
    return base_url, auth, max_page_size


def _taxii_backend() -> str:
    return os.getenv("TAXII_BACKEND", "medallion").strip().lower() or "medallion"


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


def _resolve_objects_url(collection_info: Dict) -> str:
    objects_url = collection_info.get("objects")
    if not objects_url:
        objects_url = f"{collection_info['url']}objects/" if collection_info.get("url") else None
    if not objects_url:
        collection_id = collection_info.get("id")
        api_root = collection_info.get("api_root")
        if api_root and collection_id:
            objects_url = f"{api_root}collections/{collection_id}/objects/"

    if not objects_url:
        raise RuntimeError("Unable to determine objects URL for the TAXII collection")
    return objects_url


def _fetch_objects(
    collection_info: Dict, auth: Tuple[str, str], max_page_size: int
) -> List[Dict]:
    objects_url = _resolve_objects_url(collection_info)

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


def _fetch_objects_page(
    collection_info: Dict,
    auth: Tuple[str, str],
    limit: int,
    next_token: Optional[str] = None,
) -> Tuple[List[Dict], Optional[str]]:
    objects_url = _resolve_objects_url(collection_info)
    headers = {"Accept": ACCEPT_HEADER}
    page_url = _build_page_url(objects_url, limit, next_token)
    response = requests.get(page_url, headers=headers, auth=auth, timeout=10)
    response.raise_for_status()
    payload = response.json()
    return payload.get("objects", []), payload.get("next")


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


def _parse_iso_datetime(timestamp: str) -> Optional[datetime]:
    if not timestamp:
        return None
    ts = timestamp
    if ts.endswith("Z"):
        ts = f"{ts[:-1]}+00:00"
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_taxii1_timestamp(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    return _parse_iso_datetime(text)


def _taxii1_timestamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _taxii1_build_poll_request(
    collection_name: str, begin_timestamp: Optional[datetime]
) -> str:
    return f"""
    <taxii_11:Poll_Request
      xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1"
      message_id="1"
      collection_name="{collection_name}">
      <taxii_11:Poll_Parameters>
        <taxii_11:Response_Type>FULL</taxii_11:Response_Type>
        <taxii_11:Content_Binding binding_id="urn:stix.mitre.org:xml:1.2" />
      </taxii_11:Poll_Parameters>
    </taxii_11:Poll_Request>
    """.strip()


def _taxii1_poll(
    base_url: str,
    auth: Tuple[str, str],
    collection_name: str,
    begin_timestamp: Optional[datetime],
) -> List[Dict]:
    poll_url = f"{base_url.rstrip('/')}/services/poll"
    payload = _taxii1_build_poll_request(collection_name, begin_timestamp)
    response = requests.post(
        poll_url,
        data=payload.encode("utf-8"),
        headers=TAXII1_HEADERS,
        auth=auth,
        timeout=15,
    )
    response.raise_for_status()
    if 'status_type="FAILURE"' in response.text:
        raise RuntimeError(response.text[:2000])
    items = _parse_taxii1_poll_response(response.text)
    if begin_timestamp is None:
        return items
    filtered = []
    for item in items:
        ts = _parse_taxii1_timestamp(item.get("valid_from") or item.get("created"))
        if ts is None or ts >= begin_timestamp:
            filtered.append(item)
    return filtered


def _parse_taxii1_poll_response(xml_text: str) -> List[Dict]:
    items: List[Dict] = []
    root = ET.fromstring(xml_text)
    content_blocks = root.findall(".//taxii_11:Content_Block", TAXII1_NS)
    poll_time = datetime.now(timezone.utc)
    poll_time_iso = poll_time.isoformat().replace("+00:00", "Z")

    for block in content_blocks:
        content = block.find("taxii_11:Content", TAXII1_NS)
        if content is None:
            continue
        stix_children = list(content)
        stix_root = None
        if stix_children:
            stix_root = stix_children[0]
        else:
            text = (content.text or "").strip()
            if text:
                try:
                    stix_root = ET.fromstring(text)
                except ET.ParseError:
                    stix_root = None
        if stix_root is None:
            continue
        indicators = stix_root.findall(".//stix:Indicator", TAXII1_NS)
        if not indicators:
            indicators = stix_root.findall(".//indicator:Indicator", TAXII1_NS)
        for indicator in indicators:
            parsed = _parse_taxii1_indicator(indicator, poll_time_iso)
            if parsed:
                items.append(parsed)
    return items


def _parse_taxii1_indicator(
    indicator: ET.Element, poll_time_iso: str
) -> Optional[Dict]:
    indicator_id = indicator.get("id")
    title = indicator.findtext("indicator:Title", default="", namespaces=TAXII1_NS).strip()
    description = indicator.findtext(
        "indicator:Description", default="", namespaces=TAXII1_NS
    ).strip()

    timestamp = None
    for path in (
        ".//indicator:Valid_Time_Position/indicator:Start_Time",
        ".//indicator:Produced_Time",
        ".//indicator:Created_Time",
        ".//stixCommon:Timestamp",
    ):
        timestamp = indicator.findtext(path, namespaces=TAXII1_NS)
        if timestamp:
            break
    timestamp = timestamp or poll_time_iso

    ip_value = indicator.findtext(".//AddressObj:Address_Value", namespaces=TAXII1_NS)
    domain_value = indicator.findtext(".//DomainNameObj:Value", namespaces=TAXII1_NS)
    url_value = indicator.findtext(".//URIObj:Value", namespaces=TAXII1_NS)

    pattern = None
    profile_ip = None
    if ip_value:
        profile_ip = ip_value
        pattern = f"[ipv4-addr:value = '{ip_value}']"
    elif domain_value:
        pattern = f"[domain-name:value = '{domain_value}']"
    elif url_value:
        pattern = f"[url:value = '{url_value}']"

    if not indicator_id:
        indicator_id = f"indicator--{hash((title, pattern, timestamp))}"

    return {
        "type": "indicator",
        "id": indicator_id,
        "name": title or "OpenTAXII Indicator",
        "description": description or None,
        "pattern": pattern or "",
        "pattern_type": "stix",
        "labels": ["info"],
        "valid_from": timestamp,
        "created": timestamp,
        "modified": timestamp,
        "x_slips_threat_level": "info",
        "x_slips_profile_ip": profile_ip,
        "x_slips_evidence_id": indicator_id,
    }


def _refresh_taxii1_cache(base_url: str, auth: Tuple[str, str]) -> None:
    now = datetime.now(timezone.utc)
    with _TAXII1_LOCK:
        last_poll = _TAXII1_CACHE.get("last_poll")
        begin = None
        if last_poll is not None:
            begin = last_poll
        elif TAXII1_LOOKBACK_HOURS > 0:
            begin = now - timedelta(hours=TAXII1_LOOKBACK_HOURS)

        items = _taxii1_poll(base_url, auth, DEFAULT_COLLECTION_TITLE, begin)
        if items:
            for item in items:
                item_id = item.get("id")
                if not item_id or item_id in _TAXII1_CACHE["ids"]:
                    continue
                _TAXII1_CACHE["ids"].add(item_id)
                _TAXII1_CACHE["items"].append(item)

            def _sort_key(entry: Dict) -> str:
                return entry.get("valid_from") or entry.get("created") or ""

            _TAXII1_CACHE["items"].sort(key=_sort_key, reverse=True)
            if TAXII1_CACHE_MAX and len(_TAXII1_CACHE["items"]) > TAXII1_CACHE_MAX:
                trimmed = _TAXII1_CACHE["items"][TAXII1_CACHE_MAX:]
                _TAXII1_CACHE["items"] = _TAXII1_CACHE["items"][:TAXII1_CACHE_MAX]
                for entry in trimmed:
                    item_id = entry.get("id")
                    if item_id:
                        _TAXII1_CACHE["ids"].discard(item_id)

        _TAXII1_CACHE["last_poll"] = now
        _TAXII1_CACHE["last_poll_ts"] = now.timestamp()


def _parse_when(indicator: Dict) -> datetime:
    ts = indicator.get("valid_from") or indicator.get("created")
    parsed = _parse_iso_datetime(ts)
    if parsed is not None:
        return parsed
    return datetime.utcnow().replace(tzinfo=timezone.utc)


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
        ti_source = indicator.get("x_slips_attacker_ti")
        if isinstance(ti_source, list):
            ti_source = ", ".join(str(entry) for entry in ti_source)
        profile_ip = indicator.get("x_slips_profile_ip")
        victim_ip = indicator.get("x_slips_victim")
        created_ts = indicator.get("created")
        created_dt = _parse_iso_datetime(created_ts)
        time_diff_seconds = None
        if created_dt is not None and dt_obj is not None:
            time_diff_seconds = int(round(abs((created_dt - dt_obj).total_seconds())))

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
                "profile_ip": profile_ip,
                "direction": indicator.get("x_slips_attacker_direction"),
                "victim": victim_ip,
                "created": indicator.get("created"),
                "modified": indicator.get("modified"),
                "time_diff_seconds": time_diff_seconds,
                "ti_source": ti_source,
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


def get_dashboard_payload(
    limit: Optional[int] = None, next_token: Optional[str] = None
) -> Dict:
    try:
        backend = _taxii_backend()
        base_url, auth, page_size = _load_medallion_config()

        if backend == "opentaxii":
            _refresh_taxii1_cache(base_url, auth)
            with _TAXII1_LOCK:
                items = list(_TAXII1_CACHE["items"])

            effective_limit = page_size
            if isinstance(limit, int) and limit > 0:
                effective_limit = min(limit, page_size) if page_size else limit

            offset = 0
            if next_token:
                try:
                    offset = int(next_token)
                except ValueError:
                    offset = 0

            page_items = items[offset : offset + effective_limit]
            next_offset = offset + effective_limit
            next_token_out = str(next_offset) if next_offset < len(items) else None

            evidences = _prepare_evidences(page_items)
            timeline = _build_timeline(evidences)
            ip_summary = _summarize_ips(evidences)
            summary = {
                "total_evidences": len(evidences),
                "unique_ips": len(ip_summary),
                "critical": sum(1 for e in evidences if e["severity"] == "critical"),
                "high": sum(1 for e in evidences if e["severity"] == "high"),
                "collection": DEFAULT_COLLECTION_TITLE,
            }

            return {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "timeline": timeline,
                "ip_summary": ip_summary,
                "evidences": evidences,
                "summary": summary,
                "severity_order": SEVERITY_ORDER,
                "page": {
                    "limit": effective_limit,
                    "next": next_token_out,
                },
                "backend": backend,
            }

        api_root = _discover_api_root(base_url, auth)
        collection = _select_collection(api_root, auth)
        collection.setdefault("api_root", api_root)
        collection.setdefault("url", f"{api_root}collections/{collection.get('id')}/")
        effective_limit = page_size
        if isinstance(limit, int) and limit > 0:
            effective_limit = min(limit, page_size) if page_size else limit

        objects, next_token_out = _fetch_objects_page(
            collection, auth, effective_limit, next_token
        )

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
            "page": {
                "limit": effective_limit,
                "next": next_token_out,
            },
            "backend": backend,
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


def clear_alerts_collection() -> Dict[str, object]:
    backend = _taxii_backend()
    if backend == "opentaxii":
        raise RuntimeError("Clear alerts is not supported for OpenTAXII.")

    base_url, auth, page_size = _load_medallion_config()
    api_root = _discover_api_root(base_url, auth)
    collection = _select_collection(api_root, auth)
    collection.setdefault("api_root", api_root)
    collection.setdefault("url", f"{api_root}collections/{collection.get('id')}/")

    objects = _fetch_objects(collection, auth, page_size)
    object_ids = {obj.get("id") for obj in objects if obj.get("id")}
    objects_url = _resolve_objects_url(collection).rstrip("/")

    deleted = 0
    for object_id in object_ids:
        response = requests.delete(
            f"{objects_url}/{object_id}/",
            headers={"Accept": ACCEPT_HEADER},
            auth=auth,
            timeout=10,
        )
        if response.status_code == 404:
            continue
        response.raise_for_status()
        deleted += 1

    return {
        "deleted": deleted,
        "collection": collection.get("title") or collection.get("id"),
    }
