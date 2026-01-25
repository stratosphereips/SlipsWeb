#!/usr/bin/env python3
import argparse
import base64
import json
import os
import sys
import urllib.request
from urllib.parse import urlencode


def _auth_header(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def _fetch_page(base_url: str, headers: dict, limit: int, next_token: str) -> dict:
    params = {"limit": str(limit)}
    if next_token:
        params["next"] = next_token
    url = f"{base_url}?{urlencode(params)}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as response:
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} while fetching {url}")
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Count objects in a Medallion TAXII collection."
    )
    parser.add_argument("--host", default="127.0.0.1", help="Medallion host")
    parser.add_argument("--port", default="1234", help="Medallion port")
    parser.add_argument(
        "--user",
        default=os.getenv("MEDALLION_USERNAME") or os.getenv("TAXII_USERNAME") or "admin",
        help="Basic auth username",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("MEDALLION_PASSWORD") or os.getenv("TAXII_PASSWORD") or "",
        help="Basic auth password",
    )
    parser.add_argument(
        "--collection",
        default="collection--slips-alerts",
        help="Collection id (or title if you use a different endpoint)",
    )
    parser.add_argument("--limit", type=int, default=100, help="Page size")
    args = parser.parse_args()

    base_url = (
        f"http://{args.host}:{args.port}/alerts/collections/{args.collection}/objects/"
    )
    if not args.password:
        print("Missing password. Set MEDALLION_PASSWORD or pass --password.", file=sys.stderr)
        return 2

    headers = {
        "Accept": "application/taxii+json;version=2.1",
        "Authorization": _auth_header(args.user, args.password),
    }

    total = 0
    next_token = None
    while True:
        payload = _fetch_page(base_url, headers, args.limit, next_token)
        total += len(payload.get("objects", []))
        next_token = payload.get("next")
        if not next_token:
            break

    print(total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
