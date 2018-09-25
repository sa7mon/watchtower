# Notes

## Links
* [WiFi RSN Information](https://community.arubanetworks.com/t5/Technology-Blog/A-closer-look-at-WiFi-Security-IE-Information-Elements/ba-p/198867)
* [Hostapd info](https://wireless.wiki.kernel.org/en/users/documentation/hostapd#wireless_interface)

## hostapd
* **auth_algs** = 1 - WPA, 2 - WEP, 3 - Both
* **wpa** = 1 - WPA1, 2 - WPA2, 3 - Both
* **wpa_pairwise** = WPA's data encryption
* **rsn_pairwise** = WPA2's data encryption


### Common
```
interface=wlan0       # the interface used by the AP
hw_mode=g             # g simply means 2.4GHz band
channel=10            # the channel to use
ieee80211d=1          # limit the frequencies used to those allowed in the country
country_code=US       # the country code
ieee80211n=1          # 802.11n support
wmm_enabled=1         # QoS support
ssid=somename         # the name of the AP
```

### +

### WPA2-PSK-CCMP
```
auth_algs=1          
wpa=2                
wpa_key_mgmt=WPA-PSK  
rsn_pairwise=CCMP
wpa_passphrase=somepassword
```

### WPA2-PSK-TKIP
```
auth_algs=1          
wpa=2                
wpa_key_mgmt=WPA-PSK  
rsn_pairwise=TKIP
wpa_passphrase=somepassword
```
