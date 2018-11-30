# watchtower


## Setup Instructions

1. Clone project repo
2. Create virtualenv
3. Clone Scapy git repo
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
