#!/usr/bin/env python

# https://charlesreid1.com/wiki/Scapy/Airodump_Clone#The_Script

import sys, os, signal
from multiprocessing import Process
import json
import random
import time
from scapy.all import *

interface = ''  # monitor interface
aps = {}  # dictionary to store unique APs
clients = {}


def noise_filter(addr1, addr2):
    # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:'] # possibly add our detecting MAC address

    for i in ignore:
        if i in addr1 or i in addr2:
            return True


def sniffAP(pkt):
    if pkt.haslayer(Dot11):

        # p.show()
        # ssid = p[Dot11Elt].info.decode('UTF-8')
        # bssid = str(p[Dot11].addr3).upper()
        # channel = int(ord(p[Dot11Elt:3].info))
        # capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
        #         {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        # sourceMAC = str(p[Dot11].addr2).upper()

        if pkt.addr1 and pkt.addr2:
            pkt.addr1 = pkt.addr1.lower()
            pkt.addr2 = pkt.addr2.lower()

            # Filter out all other APs and clients if asked
            # if args.accesspoint:
            #     if args.accesspoint not in [pkt.addr1, pkt.addr2]:
            #         return

            # Check if it's added to our AP list
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                apmac = pkt[Dot11].addr3
                if apmac not in aps.keys():
                    aps[apmac] = pkt[Dot11Elt].info.decode('UTF-8')
                    return

            # Ignore all the noisy packets like spanning tree

            if noise_filter(pkt.addr1, pkt.addr2):
                return

            # Management = 1, data = 2
            if pkt.type in [1, 2]:
                # clients_APs_add(clients_APs, pkt.addr1, pkt.addr2)
                if pkt.addr1 in aps.keys():
                    print("Client:  ", aps[pkt.addr1], " - ", pkt.addr2)
                elif pkt.addr2 in aps.keys():
                    print("Client: ", pkt.addr1, " - ", aps[pkt.addr2])
                else:
                    print("Client: ", pkt.addr1, " - ", pkt.addr2)


# Channel hopper
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1, 13)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break


# Capture interrupt signal and cleanup before exiting
def signal_handler(signal, frame):
    p.terminate()
    p.join()

    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage %s monitor_interface".format(sys.argv[0]))
        sys.exit(1)

    interface = sys.argv[1]

    with open('config.json') as f:
        config = json.load(f)

    # Start the channel hopper
    p = Process(target=channel_hopper)
    p.start()

    # Capture CTRL-C
    signal.signal(signal.SIGINT, signal_handler)

    # print("\nSTATUS  CHAN ENC        MAC         SSID")
    # print("========================================")
    # Start the sniffer
    sniff(iface=interface, prn=sniffAP, store=0)
