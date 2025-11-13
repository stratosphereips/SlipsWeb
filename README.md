# SlipsWeb

SlipsWeb is a local webpage that reads information from a TAXII server in order to show the details of alerts in a Slips intrusion detection system.


## Install

The installation steps to make StratosphereWeb are
1. Install a TAXII server using this repository.
2. Make one or more Slips send alerts that TAXII server by following the instructions [here](https://stratospherelinuxips.readthedocs.io/en/develop/exporting.html).
3. Start the StratosphereWeb program, configured to read from that TAXII server.


## 1. Install the Medallion TAXII server

To have a minimal setup, Slips uses Medallion as its TAXII server. 

Follow these instructions

```
python -m venv venv
source venv/bin/activate
pip install medallion stix2 taxii2-client
```


## 2. Configure the medallion server
The main configuration of the Meddalion server is in `config/medallion_config.json`

In there you need to check

- The IP address were the server will run. You can use 127.0.0.1 if Slips is running on the same computer. Or a specific IP or 0.0.0.0 for all the interfaces.
- Change the password of the Medallion server. And be sure the same password is in the `config/slips.yaml` file of Slips
- Change the port if you dont want to use 1234

## 3. Run the medallion server

The Medallion server run in the same computer as Slips, and then Medallion can listen in localhost.

`./medallion_luncher.py`

For now the medallion server will not stay in the background, but it can.

Now that the Medallion server is running. Slips can export to it. 

### Check Medallion works correclty

You can run this curl to check if medallion is working

`curl -H "Accept: application/taxii+json;version=2.1" -u admin:changeme_before_installin
g_a_medallion_server http://localhost:1234/alerts/collections/`


## 4. Exporting from Slips to Medallion TAXII Server
Follow the configuration of Slips for exporting to a TAXII server as described in [here](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/master/docs/exporting.md#stix).

Then run Slips and check that it is connecting to the Medallion server by searching for the following text in its output or log

```
[Main] Starting the module Exporting Alerts (Export alerts to slack or STIX format) [PID 1865267]
[StixExporter] Successfully exported 56 indicators to TAXII collection 'Alerts'.
```

Also be sure that in the corresponding output folder there is a file called `STIX_data.json`, which holds all the alerts exported.

Remember that only when Slips runs in an interface it sends the Alerts in real time. When run on files it will send at the end of the analysis.

## 5. Run the SlipsWeb dashboard

The dashboard is a small Flask application that periodically queries the TAXII
collection and renders a live view of the evidences.

```
cd SlipsWeb
python -m venv venv
source venv/bin/activate
FLASK_APP=app.py flask run --reload
```

The UI will be available at <http://127.0.0.1:5000>. It automatically refreshes
every few seconds, displaying timeline charts, the list of suspect IPs, and the
details of each evidence produced by Slips.

## Run SlipsWeb and Medallion inside Docker

The `SlipsWeb/Dockerfile` bundles both the Medallion TAXII server and the Flask
dashboard so you can expose them to the rest of your network with a single
container.

1. Adjust `config/medallion_config.json` (credentials, default data, etc.). The
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
     -v "$(pwd)/config:/app/config" \
     slipsweb
   ```
   The `-d` flag detaches from the container so your terminal remains free; use
   `docker logs -f slipsweb` to watch its output.

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
