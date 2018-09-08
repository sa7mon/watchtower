#!/usr/bin/env python

# from: https://gist.githubusercontent.com/nevdull77/10605115/raw/a2c10a3fee579b1e64404ac1266ca24589e4d3f5/sniff.py

from scapy.all import *
import sys

aps = set()


def findAPs(p):
    if p.haslayer(Dot11) and p.type == 0 and p.subtype == 0x08 and hasattr(p, 'info'):
        ssid = ( len(p.info) > 0 and p.info != "\x00" ) and p.info or '<hidden>'
        mac = p.addr2
        if mac not in aps:
            aps.add(mac)
            print('SSID: ' + str(ssid) + ', MAC: ' + str(mac))


if len(sys.argv) < 2:
    print("usage: sniff.py <interface>")
    sys.exit(-1)

sniff(iface=sys.argv[1], prn=findAPs)