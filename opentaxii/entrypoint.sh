#!/usr/bin/env bash
set -euo pipefail

TEMPLATE_DIR="${OPENTAXII_TEMPLATE_DIR:-/templates}"
OUTPUT_DIR="${OPENTAXII_OUTPUT_DIR:-/input}"

: "${OPENTAXII_DB_USER:?Missing OPENTAXII_DB_USER}"
: "${OPENTAXII_DB_PASSWORD:?Missing OPENTAXII_DB_PASSWORD}"
: "${OPENTAXII_AUTH_SECRET:?Missing OPENTAXII_AUTH_SECRET}"
: "${OPENTAXII_TAXII_USERNAME:?Missing OPENTAXII_TAXII_USERNAME}"
: "${OPENTAXII_TAXII_PASSWORD:?Missing OPENTAXII_TAXII_PASSWORD}"

render_template() {
  local template_path="$1"
  local output_path="$2"
  python - <<PY
import os
from pathlib import Path

template = Path("${template_path}").read_text(encoding="utf-8")
replacements = {
    "OPENTAXII_DB_USER": os.environ["OPENTAXII_DB_USER"],
    "OPENTAXII_DB_PASSWORD": os.environ["OPENTAXII_DB_PASSWORD"],
    "OPENTAXII_AUTH_SECRET": os.environ["OPENTAXII_AUTH_SECRET"],
    "OPENTAXII_TAXII_USERNAME": os.environ["OPENTAXII_TAXII_USERNAME"],
    "OPENTAXII_TAXII_PASSWORD": os.environ["OPENTAXII_TAXII_PASSWORD"],
}
for key, value in replacements.items():
    template = template.replace(f"{{{{{key}}}}}", value)
Path("${output_path}").write_text(template, encoding="utf-8")
PY
}

mkdir -p "${OUTPUT_DIR}"
render_template "${TEMPLATE_DIR}/opentaxii.yml.tmpl" "${OUTPUT_DIR}/opentaxii.yml"
render_template "${TEMPLATE_DIR}/data-configuration.yml.tmpl" "${OUTPUT_DIR}/data-configuration.yml"

export OPENTAXII_CONFIG="${OUTPUT_DIR}/opentaxii.yml"

exec /entrypoint.sh "$@"
