#!/usr/bin/env python

# from: https://gist.githubusercontent.com/nevdull77/10605115/raw/a2c10a3fee579b1e64404ac1266ca24589e4d3f5/sniff.py

from scapy.all import *
import sys
import json

ssids = set()

def findAPs(p):
    p.show()
    if p.haslayer(Dot11) and p.type == 0 and p.subtype == 0x08 and hasattr(p, 'info'):
        ssid = ( len(p.info) > 0 and p.info != "\x00" ) and p.info or '<hidden>'
        if type(ssid) == bytes:
            ssid = ssid.decode('UTF-8')
        # ssid is now definitely a string

        mac = p.addr2
        if ssid not in ssids:
            print("New SSID: " + ssid)
            ssids.add(ssid)

        if ssid == config['ssid']:
            if mac not in config['macs']:
                print('SSID: ' + str(ssid) + ', BAD MAC: ' + str(mac))
            else:
                print('SSID: ' + str(ssid) + ', GOOD MAC: ' + str(mac))


if len(sys.argv) < 2:
    print("usage: sniff.py <interface>")
    sys.exit(-1)

with open('config.json') as f:
    config = json.load(f)

sniff(iface=sys.argv[1], prn=findAPs, store=0)