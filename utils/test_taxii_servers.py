#!/usr/bin/env python3
import argparse
import os
import sys
import textwrap
import uuid
from datetime import datetime, timezone
from typing import Optional

import requests
from requests.auth import HTTPBasicAuth

DEFAULT_TIMEOUT = 10


def _auth(user: Optional[str], password: Optional[str]):
    if user and password:
        return HTTPBasicAuth(user, password)
    return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _print_result(label: str, response: requests.Response) -> bool:
    ok = response.ok
    status = f"{response.status_code} {response.reason}"
    print(f"{label}: {status}")
    if not ok:
        snippet = response.text.strip()
        if len(snippet) > 800:
            snippet = f"{snippet[:800]}..."
        if snippet:
            print(snippet)
    return ok


def test_medallion(args: argparse.Namespace) -> int:
    base_url = f"http://{args.host}:{args.port}"
    auth = _auth(args.user, args.password)
    headers = {"Accept": "application/taxii+json;version=2.1"}

    discovery = f"{base_url}/taxii2/"
    resp = requests.get(discovery, headers=headers, auth=auth, timeout=DEFAULT_TIMEOUT)
    if not _print_result("Medallion discovery", resp):
        return 1

    collections_url = f"{base_url}/{args.api_root.strip('/')}/collections/"
    resp = requests.get(collections_url, headers=headers, auth=auth, timeout=DEFAULT_TIMEOUT)
    if not _print_result("Medallion collections", resp):
        return 1

    indicator_id = f"indicator--{uuid.uuid4()}"
    now = _now_iso()
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now,
        "modified": now,
        "name": "SlipsWeb test indicator",
        "pattern": "[ipv4-addr:value = '203.0.113.123']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": now,
        "labels": ["test"],
    }
    envelope = {"objects": [indicator]}

    objects_url = (
        f"{base_url}/{args.api_root.strip('/')}/collections/"
        f"{args.collection}/objects/"
    )
    headers = {
        "Accept": "application/taxii+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1",
    }
    resp = requests.post(
        objects_url,
        json=envelope,
        headers=headers,
        auth=auth,
        timeout=DEFAULT_TIMEOUT,
    )
    ok = _print_result("Medallion insert", resp)
    if ok:
        print(f"Inserted test object: {indicator_id}")
    return 0 if ok else 1


def _build_stix_package(indicator_id: str) -> str:
    stix_xml = f"""
    <stix:STIX_Package
      xmlns:stix=\"http://stix.mitre.org/stix-1\"
      xmlns:indicator=\"http://stix.mitre.org/Indicator-2\"
      xmlns:cybox=\"http://cybox.mitre.org/cybox-2\"
      xmlns:AddressObj=\"http://cybox.mitre.org/objects#AddressObject-2\"
      xmlns:stixCommon=\"http://stix.mitre.org/common-1\"
      xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
      id=\"example:STIXPackage-1\"
      version=\"1.2\">
      <stix:STIX_Header>
        <stix:Title>SlipsWeb OpenTAXII test alert</stix:Title>
      </stix:STIX_Header>
      <stix:Indicators>
        <stix:Indicator id=\"{indicator_id}\" xsi:type=\"indicator:IndicatorType\">
          <indicator:Title>SlipsWeb test indicator</indicator:Title>
          <indicator:Observable>
            <cybox:Object>
              <cybox:Properties xsi:type=\"AddressObj:AddressObjectType\" category=\"ipv4-addr\">
                <AddressObj:Address_Value>203.0.113.123</AddressObj:Address_Value>
              </cybox:Properties>
            </cybox:Object>
          </indicator:Observable>
        </stix:Indicator>
      </stix:Indicators>
    </stix:STIX_Package>
    """
    return textwrap.dedent(stix_xml).strip()


def test_opentaxii(args: argparse.Namespace) -> int:
    base_url = f"http://{args.host}:{args.port}"
    auth = _auth(args.user, args.password)
    headers = {
        "Content-Type": "application/xml",
        "Accept": "application/xml",
        "X-TAXII-Content-Type": "urn:taxii.mitre.org:message:xml:1.1",
        "X-TAXII-Accept": "urn:taxii.mitre.org:message:xml:1.1",
        "X-TAXII-Protocol": "urn:taxii.mitre.org:protocol:http:1.0",
        "X-TAXII-Services": "urn:taxii.mitre.org:services:1.1",
    }

    discovery_xml = f"""
    <taxii_11:Discovery_Request
      xmlns:taxii_11=\"http://taxii.mitre.org/messages/taxii_xml_binding-1.1\"
      message_id=\"{uuid.uuid4()}\"/>
    """
    resp = requests.post(
        f"{base_url}/services/discovery",
        data=textwrap.dedent(discovery_xml).strip(),
        headers=headers,
        auth=auth,
        timeout=DEFAULT_TIMEOUT,
    )
    if not _print_result("OpenTAXII discovery", resp):
        return 1

    indicator_id = f"example:indicator-{uuid.uuid4()}"
    stix_xml = _build_stix_package(indicator_id)
    inbox_xml = f"""
    <taxii_11:Inbox_Message
      xmlns:taxii_11=\"http://taxii.mitre.org/messages/taxii_xml_binding-1.1\"
      message_id=\"{uuid.uuid4()}\">
      <taxii_11:Destination_Collection_Names>
        <taxii_11:Collection_Name>{args.collection}</taxii_11:Collection_Name>
      </taxii_11:Destination_Collection_Names>
      <taxii_11:Content_Block>
        <taxii_11:Content_Binding>urn:stix.mitre.org:xml:1.2</taxii_11:Content_Binding>
        <taxii_11:Content>
    {stix_xml}
        </taxii_11:Content>
      </taxii_11:Content_Block>
    </taxii_11:Inbox_Message>
    """
    resp = requests.post(
        f"{base_url}/services/inbox",
        data=textwrap.dedent(inbox_xml).strip(),
        headers=headers,
        auth=auth,
        timeout=DEFAULT_TIMEOUT,
    )
    ok = _print_result("OpenTAXII insert", resp)
    if ok:
        print(f"Inserted test object: {indicator_id}")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Smoke-test TAXII servers and insert a fake alert."
    )
    subparsers = parser.add_subparsers(dest="backend", required=True)

    med = subparsers.add_parser("medallion", help="Test Medallion (TAXII 2)")
    med.add_argument("--host", default=os.getenv("MEDALLION_HOST", "127.0.0.1"))
    med.add_argument("--port", type=int, default=int(os.getenv("MEDALLION_PORT", "1234")))
    med.add_argument("--user", default=os.getenv("MEDALLION_USERNAME"))
    med.add_argument("--password", default=os.getenv("MEDALLION_PASSWORD"))
    med.add_argument("--api-root", default="alerts")
    med.add_argument("--collection", default="collection--slips-alerts")
    med.set_defaults(func=test_medallion)

    otx = subparsers.add_parser("opentaxii", help="Test OpenTAXII (TAXII 1)")
    otx.add_argument("--host", default=os.getenv("OPENTAXII_HOST", "127.0.0.1"))
    otx.add_argument("--port", type=int, default=int(os.getenv("OPENTAXII_PORT", "1234")))
    otx.add_argument("--user", default=os.getenv("OPENTAXII_TAXII_USERNAME"))
    otx.add_argument("--password", default=os.getenv("OPENTAXII_TAXII_PASSWORD"))
    otx.add_argument("--collection", default=os.getenv("OPENTAXII_COLLECTION", "Alerts"))
    otx.set_defaults(func=test_opentaxii)

    args = parser.parse_args()
    if args.user is None or args.password is None:
        print("Missing credentials. Provide --user/--password or set env vars.")
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
