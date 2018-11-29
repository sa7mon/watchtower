# watchtower


### Notifications
* Alerts with Grafana
* Pushbullet
* Slack bot
* IFTTT


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
