# SlipsWeb

SlipsWeb bundles two pieces: a TAXII server and a web UI that reads from that
TAXII server to visualize Slips alerts. You do not need to install a separate
TAXII server.

There are **two TAXII backends** you can choose from:

- **Medallion (TAXII 2.1, in‑memory)**: simple, fast to start, no persistence.
- **OpenTAXII (TAXII 1.x, Postgres)**: persistent storage, but TAXII 1.x
  (Slips currently uses TAXII 2 endpoints).

## Overview

1. Configure Slips to export alerts to the TAXII server running here (see the
   STIX/TAXII section in the docs).
2. Start the SlipsWeb stack (TAXII server + web UI).
3. Open the web UI and inspect the alerts.

## 1. Configure the Medallion server
The main Medallion settings (host, port, data file) live in
`config/medallion_config.json`.

Credentials are **not stored in the config file**. Set them through
environment variables when you start Medallion:

- `MEDALLION_USERNAME`
- `MEDALLION_PASSWORD`

Make sure the same values are used in Slips (`taxii_username` /
`taxii_password` in `config/slips.yaml`).

## 2. Run the Medallion server

The Medallion server run in the same computer as Slips, and then Medallion can listen in localhost.

`MEDALLION_USERNAME=admin MEDALLION_PASSWORD=changeme_before_installing_a_medallion_server python medallion_server.py`

For now the medallion server will not stay in the background, but it can.

Now that the Medallion server is running. Slips can export to it. 

### Check Medallion works correctly

You can run this curl to check if medallion is working

`curl -H "Accept: application/taxii+json;version=2.1" -u "$MEDALLION_USERNAME:$MEDALLION_PASSWORD" http://localhost:1234/alerts/collections/`


## 3. Exporting from Slips to Medallion TAXII Server
Follow the configuration of Slips for exporting to a TAXII server as described in [here](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/master/docs/exporting.md#stix).
Make sure `taxii_username` / `taxii_password` in `config/slips.yaml` match the
credentials you set in `.env`.

Then run Slips and check that it is connecting to the Medallion server by searching for the following text in its output or log

```
[Main] Starting the module Exporting Alerts (Export alerts to slack or STIX format) [PID 1865267]
[StixExporter] Successfully exported 56 indicators to TAXII collection 'Alerts'.
```

Also be sure that in the corresponding output folder there is a file called `STIX_data.json`, which holds all the alerts exported.

Remember that only when Slips runs in an interface it sends the Alerts in real time. When run on files it will send at the end of the analysis.

## 4. Run the SlipsWeb dashboard

The dashboard is a small Flask application that periodically queries the TAXII
collection and renders a live view of the evidences.

```
cd SlipsWeb
FLASK_APP=app.py flask run --reload
```

The UI will be available at <http://127.0.0.1:5000>. It automatically refreshes
every few seconds, displaying timeline charts, the list of suspect IPs, and the
details of each evidence produced by Slips.
Set `TAXII_USERNAME` / `TAXII_PASSWORD` (or reuse `MEDALLION_USERNAME` /
`MEDALLION_PASSWORD`) so the UI can authenticate to the TAXII server.

## Docker Compose (choose Medallion or OpenTAXII)

Use Docker Compose to run **separate containers** and clearly choose the TAXII
backend. You run **one profile at a time**:

- `medallion` → Medallion TAXII 2 server (in-memory)
- `opentaxii` → OpenTAXII + PostgreSQL (persistent)

### 1) Put **all secrets** in `.env`

Only usernames/passwords go in `.env` (never in YAML files):

```
MEDALLION_USERNAME=admin
MEDALLION_PASSWORD=changeme_before_installing_a_medallion_server

OPENTAXII_DB_USER=opentaxii
OPENTAXII_DB_PASSWORD=opentaxii
OPENTAXII_AUTH_SECRET=changeme

OPENTAXII_TAXII_USERNAME=admin
OPENTAXII_TAXII_PASSWORD=admin
```

Copy the template and edit it:

```bash
cd SlipsWeb
cp .env.example .env
```

Then open `.env` and replace the default usernames/passwords with your own.
The `.env` file is ignored by git.

### 2) Put **non‑secret config** in YAML/JSON

- **Medallion settings** (host, port, data file):
  `config/medallion_config.json`
- **OpenTAXII settings** (collections, services, limits):
  `config/opentaxii/opentaxii.yml.tmpl` and
  `config/opentaxii/data-configuration.yml.tmpl`
  (credentials are injected at runtime from `.env`)

### 3) Start the stack you want

**Medallion (TAXII 2, in-memory):**

```bash
docker compose --profile medallion up -d --build
```

This starts **`slipsweb-medallion`** + **`medallion`**.
The UI connects to `http://medallion:1234`.

If you only run `... up ... medallion`, you will start **only** the TAXII
server (no web UI). To bring both up, omit the service name or run:

```bash
docker compose --profile medallion up -d --build slipsweb-medallion medallion
```

**OpenTAXII + Postgres (persistent):**

```bash
docker compose --profile opentaxii up -d --build
```

This starts **`slipsweb-opentaxii`**, **`opentaxii`**, and **`opentaxii-db`**.
OpenTAXII listens on container port `9000` and is published on host port `1234`.
Postgres data is stored in the `opentaxii_pgdata` volume.

### 3b) Stop the stack

Always pass the `.env` file so Compose can interpolate required variables.

Stop the profile you started:

```bash
docker compose --env-file .env --profile medallion down
```

```bash
docker compose --env-file .env --profile opentaxii down
```

Stop **all** SlipsWeb containers created by this Compose file (regardless of profile):

```bash
docker compose --env-file .env down --remove-orphans
```

### 4) Point Slips to the right TAXII server

In `config/slips.yaml` set:

- `TAXII_server`: `localhost` (if Slips runs on the same host)
  or `medallion` / `opentaxii` (if Slips runs in the same Docker network)
- `port`: `1234`
- `discovery_path`: `/taxii2/`
- `taxii_username` / `taxii_password`: match the `.env` credentials

Notes:
- Do not run both profiles at once unless you change host ports (both publish
  to `1234` by default).
- OpenTAXII uses template files from `config/opentaxii/`; credentials are
  injected at runtime from `.env` so nothing sensitive is committed.
- SlipsWeb uses TAXII 2 endpoints (e.g., `/taxii2/`). OpenTAXII's open-source
  defaults are TAXII 1.x, so you may need to enable TAXII 2 support or use a
  TAXII 2-capable server.

## Run SlipsWeb and Medallion inside Docker

The `SlipsWeb/Dockerfile` bundles both the Medallion TAXII server and the Flask
dashboard so you can expose them to the rest of your network with a single
container.

1. Adjust `config/medallion_config.json` (host, port, default data, etc.). The
   default config already binds Medallion to `0.0.0.0:1234`, which allows a
   Slips instance running outside Docker to reach it through the mapped port.
2. Build the image from the `SlipsWeb` folder:

   ```bash
   docker build -t slipsweb .
   ```

3. Run the container and expose the TAXII (1234) and UI (5000) ports to your
   host. Mount the `config/` directory if you want to tweak it without
   rebuilding:

   ```bash
   docker run -d --rm \
     --name slipsweb \
     -p 1234:1234 \
     -p 5000:5000 \
     -e MEDALLION_USERNAME=admin \
     -e MEDALLION_PASSWORD=changeme_before_installing_a_medallion_server \
     -v "$(pwd)/config:/app/config" \
     slipsweb
   ```
   The `-d` flag detaches from the container so your terminal remains free; use
   `docker logs -f slipsweb` to watch its output.
   If you mount `-v "$(pwd)/config:/app/config"`, ensure that
   `medallion_config.json` and `medallion_default_data.json` exist in that
   folder.

   To log every request hitting the Medallion TAXII server, enable access
   logging when you start the container:

   ```bash
   docker run -d --rm \
     --name slipsweb \
     -p 1234:1234 \
     -p 5000:5000 \
     -e MEDALLION_ACCESS_LOG=1 \
     -e MEDALLION_USERNAME=admin \
     -e MEDALLION_PASSWORD=changeme_before_installing_a_medallion_server \
     -v "$(pwd)/config:/app/config" \
     slipsweb
   ```

### Count Medallion objects

Use the helper script to count how many STIX objects are currently stored in
the Alerts collection:

```bash
python utils/count_medallion_objects.py \
  --host 127.0.0.1 \
  --port 1234 \
  --user "$MEDALLION_USERNAME" \
  --password "$MEDALLION_PASSWORD" \
  --collection collection--slips-alerts
```

If you run it from outside the container, replace `127.0.0.1` with the host/IP
where you published port 1234.

### Test TAXII servers (smoke test + fake alert)

Use the helper script to verify each TAXII backend is reachable and accepts a
test insert.

**Medallion (TAXII 2):**

```bash
python utils/test_taxii_servers.py medallion \
  --host 127.0.0.1 \
  --port 1234 \
  --user "$MEDALLION_USERNAME" \
  --password "$MEDALLION_PASSWORD"
```

**OpenTAXII (TAXII 1):**

```bash
python utils/test_taxii_servers.py opentaxii \
  --host 127.0.0.1 \
  --port 1234 \
  --user "$OPENTAXII_TAXII_USERNAME" \
  --password "$OPENTAXII_TAXII_PASSWORD"
```

The Flask UI is now reachable from a browser at <http://localhost:5000> (or the
host IP you used with `-p`). Point your external Slips deployment to the TAXII
endpoint at `http://<host-ip>:1234` so it can push alerts into the collections
served by Medallion inside the container.

### Customizing ports

You can override the container listeners without editing the Dockerfile by
setting environment variables when you start the container:

```bash
docker run --rm \
  -p 8443:8443 \
  -p 1443:1443 \
  -e FLASK_RUN_PORT=8443 \
  -e MEDALLION_PORT=1443 \
  -e MEDALLION_USERNAME=admin \
  -e MEDALLION_PASSWORD=changeme_before_installing_a_medallion_server \
  slipsweb
```

`FLASK_RUN_PORT` / `FLASK_RUN_HOST` control the dashboard, whereas
`MEDALLION_PORT` / `MEDALLION_HOST` configure the TAXII server. The `-p`
arguments still decide how those ports are published to the outside world.

### Limiting access via iptables

If the host uses a public IP, restrict who can reach the published ports by
running `limit_network_access.sh` (must be executed as root, e.g. with sudo):

```bash
cd SlipsWeb
sudo ./limit_network_access.sh 147.32.0.0/16
```

The script updates the `DOCKER-USER` chain so only that CIDR can connect to the
default ports (1234 and 5000) and drops the rest. Adjust the `PORTS` environment
variable if you changed the exposed ports, e.g. `PORTS="8443 1443" sudo ./limit_network_access.sh 147.32.0.0/16`.
