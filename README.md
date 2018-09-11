# watchtower


https://stackoverflow.com/a/27033690

https://wlan1nde.wordpress.com/2016/06/28/using-scapy-to-send-wlan-frames/


## Proposed Features
* Detection: Same SSID/security type but not known good MAC address
  * If bad AP found, try to find the manufacturer from the MAC
* Detection: Same everything settings except channel number (Make sure to watch for legitimate channel-hopping)
* Detection: Same SSID/security/MAC/everything but different signal strength (Probably find signal strength
  standard deviation)
    * https://stackoverflow.com/questions/10818661/scapy-retrieving-rssi-from-wifi-packets
* Detection: Lots of death frames originating from it? (Probably not able to impersonate
  network and deauth simultaneously)
* Detection: Possibly check if the "Data Rate" field is different. As seen in Figure 6 & 7 of '....PLCP Header'
  * https://stackoverflow.com/questions/11794602/scapy-how-do-i-get-the-full-ip-packet-header
* Detection: Follow detection method laid out in '....PLCP Header'

### Notifications
* Alerts with Grafana
* Pushbullet
* Slack bot
* IFTTT


## Dev Roadmap 
### v0.1
* Detect a RAP with same SSID but mismatched settings (WPA2-PSK & 802.1x)
   * MAC
   * Auth Type / Cipher Suite
   * Channel
* Detect deauth packets destined for clients associated with our good SSID
### v0.2
* Detect a RAP with all of the same settings, but a significantly different signal strength



## Scapy notes
https://stackoverflow.com/a/31263464
https://gist.github.com/securitytube/5291959


## Dev notes

* Couldn't get TP-Link adapter to show up on Macbook. Also `iwconfig` doesn't exist in OSX. Trying Ubuntu VM
* scapy works in Kali VM using the apt installed Scapy. Will have to see if venv works/is necessary
* `sudo pip3 install scapy` resulted in `ModuleNotFoundError: No module named 'setuptools'`
    * Needed to `sudo apt-get install python3-setuptools` then re-run pip install
* Got everything working in Kali.

Get Kali working:
```bash
sudo apt install python3-pip
sudo pip3 install virtualenv
virtualenv --python python3 watchtower-venv3
source watchtower-venv3/bin/activate
```
then
```bash
airmon-ng check kill
airmon-ng start wlan0
python3 ./sniff.py wlan0mon
```

## Sources notes

* Deauth frames are not protected in 802.11i but are encrypted in 802.11w after the 4-way handshake.
However,
there are some issues regarding the deployment of this standard, namely that
millions of devices need to be changed or upgraded. Hence, few WLANs world-
wide have implemented this standard. Thus, deauthentication/disassociation
DoS attacks remain a problem in WLANs.  - Alotaibi Khaled Elleithy
* Need to read through "Passive online detection....TCP ACK-Pairs"
