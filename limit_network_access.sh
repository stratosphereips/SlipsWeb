#!/usr/bin/env bash
# Restrict Docker-published SlipsWeb ports to a specific CIDR.
set -euo pipefail

CHAIN="${CHAIN:-DOCKER-USER}"
PORTS="${PORTS:-1234 5000}"

usage() {
  cat <<EOF
Usage: sudo $0 <CIDR>

Example:
  sudo $0 147.32.0.0/16

Environment variables:
  PORTS  Space-separated list of TCP ports to guard (default: "1234 5000")
  CHAIN  iptables chain to modify (default: DOCKER-USER)
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

if [[ $(id -u) -ne 0 ]]; then
  echo "This script must run as root (hint: sudo)." >&2
  exit 1
fi

if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables command not found." >&2
  exit 1
fi

CIDR="$1"

if ! iptables -nL "${CHAIN}" >/dev/null 2>&1; then
  echo "Chain '${CHAIN}' does not exist. Create it or adjust CHAIN env var." >&2
  exit 1
fi

insert_drop() {
  local port="$1"
  if iptables -C "${CHAIN}" -p tcp --dport "${port}" -j DROP >/dev/null 2>&1; then
    echo "[skip] DROP rule already present for port ${port}"
  else
    echo "[add] DROP rule for port ${port}"
    iptables -I "${CHAIN}" 1 -p tcp --dport "${port}" -j DROP
  fi
}

insert_accept() {
  local port="$1"
  if iptables -C "${CHAIN}" -p tcp --dport "${port}" -s "${CIDR}" -j ACCEPT >/dev/null 2>&1; then
    echo "[skip] ACCEPT rule already present for ${CIDR} on port ${port}"
  else
    echo "[add] ACCEPT ${CIDR} -> port ${port}"
    iptables -I "${CHAIN}" 1 -p tcp --dport "${port}" -s "${CIDR}" -j ACCEPT
  fi
}

for port in ${PORTS}; do
  insert_drop "${port}"
  insert_accept "${port}"
done

echo
echo "Updated ${CHAIN} chain:"
iptables -nL "${CHAIN}" --line-numbers
