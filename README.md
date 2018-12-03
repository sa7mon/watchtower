# watchtower

WatchTower is a tool created to help detect both Rogue AP and Deauth attacks. It is in early stages of development and was developed initially to fulfill the requirements of my IT662 Data Communications and Networking class.

## Setup

1. Clone project repo
2. `virtualenv --python python3 venv`
3. `git clone https://github.com/secdev/scapy.git`
4. `pip3 install scapy/`
5. `pip3 install -r requirements.txt`
6. `airmon-ng start wlan0` (where wlan0 is a WLAN adapter)
7. `python3 ./watchtower`

## config.json documentation
```json
{
  "ssid": "MyNetwork",
  "macs": [
    "51:34:98:97:46:B3"
  ],
  "channel": 6,
  "encryption": "WPA2",
  "cipher": "CCMP",
  "authentication": "PSK",
  "signalStrength": -35,
  "strengthVariance": 5,
  "checks": {
    "checkMAC": true,
    "checkChannel": false,
    "checkEncryption": true,
    "checkCipher": true,
    "checkAuthentication": true,
    "checkStrength": true
  },
  "slackWebhook": "",
  "sendSlackNotify": false
}
```
authType options:
* "WPA2"
* "WEP"
* "OPEN"

## Known issues
* In hostapd, if "wpa=" is set to 3 enabling both WPA and WPA2, we just detect it as WPA2

## Academic Paper

[PDF (12 Pages)](https://github.com/sa7mon/watchtower/files/2630394/DanSalmon-Watchtower.pdf)

## License
Because this project is based off of the Airoscapy project by Peter Kacherginsky, WatchTower is licensed under the Creative Commons “Attribution-NonCommercial-ShareAlike 4.0 International” (CC BY-NC-SA 4.0) license . Airoscapy is released under this license which re-quires material built upon it to be released under the same.
