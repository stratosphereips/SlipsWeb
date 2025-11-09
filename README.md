# StratosphereWeb

StratosphereWeb is a local webpage that reads information from a TAXII server in order to show the details of alerts in a Slips intrusion detection system.


## Install

The installation steps to make StratosphereWeb are
1. Install a TAXII server using this repository.
2. Make one or more Slips send alerts that TAXII server by following the instructions [here](https://stratospherelinuxips.readthedocs.io/en/develop/exporting.html).
3. Start the StratosphereWeb program, configured to read from that TAXII server.


## 1. Install the Medallion TAXII server

To have a minimal setup, Slips uses Medallion as its TAXII server. 

Follow these instructions

```
source venv/bin/activate
pip install medallion stix2 taxii2-client
```

Change the default config password of the TAXII servers you are going to export to in ```config/medallion_config.yaml```

Run the medallion server

The Medallion server can be in the same computer as Slips, and then Medallion can listen in localhost.
`medallion slips/medallion_config.json --host 127.0.0.1 --port 1234`

Or it can run in another computer, and then Medallion should listen in its IP or in 0.0.0.0
`medallion slips/medallion_config.json --host 0.0.0.0 --port 1234`

Now that the Medallion server is running. Slips can export to it. 

## 3. Exporting from Slips to Medallion TAXII Server
Follow the configuration of Slips for exporting to a TAXII server as described in [here](https://github.com/stratosphereips/StratosphereLinuxIPS/blob/master/docs/exporting.md#stix).