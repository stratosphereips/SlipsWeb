#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

CONFIG_PATH = Path("config/medallion_config.json")

def main():
    # Load configuration
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"❌ Failed to read {CONFIG_PATH}: {e}")
        sys.exit(1)

    host = str(cfg.get("server", {}).get("host", "127.0.0.1"))
    port = str(cfg.get("server", {}).get("port", "1234"))

    # Run medallion with the host and port from config
    cmd = [
        "medallion",
        str(CONFIG_PATH),
        "--host", host,
        "--port", port,
        "--log-level", "DEBUG"
    ]

    print(f"🚀 Starting Medallion on {host}:{port} using {CONFIG_PATH}")
    print(f"→ Command: {' '.join(cmd)}")
    subprocess.run(cmd)

if __name__ == "__main__":
    main()
