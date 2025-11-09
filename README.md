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

Change the password of the Medallion server in `config/medallion_config.json`.

## 2. Run the medallion server

The Medallion server run in the same computer as Slips, and then Medallion can listen in localhost.

`medallion config/medallion_config.json --host 127.0.0.1 --port 1234`

Or it can run in another computer, and then Medallion should listen in its IP or in 0.0.0.0

`medallion config/medallion_config.json --host 0.0.0.0 --port 1234`

Now that the Medallion server is running. Slips can export to it. 

### Check Medallion works correclty

You can run this curl to check if medallion is working

`curl -H "Accept: application/taxii+json;version=2.1" -u admin:changeme_before_installin
g_a_medallion_server http://localhost:1234/alerts/collections/`


## 3. Exporting from Slips to Medallion TAXII Server
Follow the configuration of Slips for exporting to a TAXII server as described in [here](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/master/docs/exporting.md#stix).

Then run Slips and check that it is connecting to the Medallion server by searching for the following text in its output or log

```
[Main] Starting the module Exporting Alerts (Export alerts to slack or STIX format) [PID 1865267]
[StixExporter] Successfully exported 56 indicators to TAXII collection 'Alerts'.
```

Also be sure that in the corresponding output folder there is a file called `STIX_data.json`, which holds all the alerts exported.

Remember that only when Slips runs in an interface it sends the Alerts in real time. When run on files it will send at the end of the analysis.
