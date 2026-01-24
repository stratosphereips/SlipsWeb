#!/usr/bin/env python3
import json
import logging
import os
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

from flask import g, request
from medallion import application_instance, register_blueprints, set_config

LOG_FORMAT = "[%(name)s] [%(levelname)-8s] [%(asctime)s] %(message)s"


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _setup_access_logging(app) -> None:
    logger = logging.getLogger("medallion.access")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    @app.before_request
    def _access_start() -> None:
        g._access_start = time.monotonic()

    @app.after_request
    def _access_log(response):
        duration = 0.0
        if hasattr(g, "_access_start"):
            duration = time.monotonic() - g._access_start
        path = request.full_path
        if path.endswith("?"):
            path = path[:-1]
        remote = request.headers.get("X-Forwarded-For", request.remote_addr) or "-"
        length = response.calculate_content_length()
        length = length if length is not None else 0
        logger.info(
            '%s "%s %s" %s %s %.3fs',
            remote,
            request.method,
            path,
            response.status_code,
            length,
            duration,
        )
        return response


def _rebase_url(base_url: str, original: str) -> str:
    if not original:
        return original
    parsed = urlparse(original)
    if not parsed.scheme and not parsed.netloc:
        path = original if original.startswith("/") else f"/{original}"
        return urljoin(base_url, path.lstrip("/"))
    base = urlparse(base_url)
    return urlunparse(
        base._replace(
            path=parsed.path,
            params=parsed.params,
            query=parsed.query,
            fragment=parsed.fragment,
        )
    )


def _update_discovery_urls() -> None:
    backend = getattr(application_instance, "medallion_backend", None)
    data = getattr(backend, "data", None)
    if not isinstance(data, dict):
        return
    discovery = data.get("/discovery")
    if not isinstance(discovery, dict):
        return
    base_url = request.host_url
    api_roots = discovery.get("api_roots")
    if isinstance(api_roots, list):
        discovery["api_roots"] = [
            _rebase_url(base_url, root) for root in api_roots
        ]
    default_root = discovery.get("default")
    if isinstance(default_root, str):
        discovery["default"] = _rebase_url(base_url, default_root)


def main() -> None:
    config_path = Path(os.environ.get("MEDALLION_CONFIG", "config/medallion_config.json"))
    host = os.environ.get("MEDALLION_HOST", "0.0.0.0")
    port = int(os.environ.get("MEDALLION_PORT", "1234"))
    log_level = os.environ.get("MEDALLION_LOG_LEVEL", "INFO").upper()
    access_log = _truthy(os.environ.get("MEDALLION_ACCESS_LOG", ""))

    medallion_logger = logging.getLogger("medallion")
    medallion_logger.setLevel(log_level)
    if medallion_logger.handlers:
        for handler in medallion_logger.handlers:
            handler.setFormatter(logging.Formatter(LOG_FORMAT))

    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    with config_path.open("r", encoding="utf-8") as config_file:
        configuration = json.load(config_file)

    set_config(application_instance, "users", configuration)
    set_config(application_instance, "taxii", configuration)
    set_config(application_instance, "backend", configuration)
    register_blueprints(application_instance)

    @application_instance.before_request
    def _sync_discovery_urls() -> None:
        if request.path.rstrip("/") == "/taxii2":
            _update_discovery_urls()

    if access_log:
        _setup_access_logging(application_instance)

    application_instance.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
