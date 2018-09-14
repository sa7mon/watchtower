#!/usr/bin/env python

import sys, os, signal
from multiprocessing import Process
import json
import random
import time
from scapy.all import *

interface = ''  # monitor interface
aps = {}  # dictionary to store unique APs

# process unique sniffed Beacons and ProbeResponses.
def sniffAP(p):
    if p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp):
        p.show()
        ssid = p[Dot11Elt].info.decode('UTF-8')
        bssid = p[Dot11].addr3
        channel = int(ord(p[Dot11Elt:3].info))
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

        # Check for encrypted networks
        if re.search("privacy", capability):
            enc = 'Y'
        else:
            enc = 'N'

        if ssid == config['ssid']:

            # p.show()
            # Save discovered AP
            aps[p[Dot11].addr3] = enc

            if bssid not in config['macs']:
                print("{:>2d}  {:s}  {:s} {:s} - BAD".format(int(channel), enc, bssid, ssid))
            else:
                print("{:>2d}  {:s}  {:s} {:s} - GOOD".format(int(channel), enc, bssid, ssid))
            print(str(len(aps)), " unique APs with our SSID seen")

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

    # print("\n-=-=-=-=-=  STATISTICS =-=-=-=-=-=-")
    # print("Total APs found: {:d}".format(len(aps)))
    # print("Encrypted APs  : {:d}".format(len([ap for ap in aps if aps[ap] == 'Y'])))
    # print("Unencrypted APs: {:d}".format(len([ap for ap in aps if aps[ap] == 'N'])))

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

    # Start the sniffer
    sniff(iface=interface, prn=sniffAP, store=0)
