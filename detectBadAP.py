#!/usr/bin/env python

import sys, os, signal
from multiprocessing import Process
import json
from scapy.all import *

interface = ''  # monitor interface
aps = set()  # dictionary to store unique APs


def checkAP(ap_ssid, ap_mac, ap_channel, ap_enc):
    if config['checks']['checkMAC']:
        if ap_mac.upper() not in config['macs']:
            return False

    if config['checks']['checkChannel']:
        if ap_channel != config['channel']:
            return False

    # if config['checks']['checkAuthType']:

    return True

# process unique sniffed Beacons and ProbeResponses.
def sniffAP(p):
    if p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp):
        # p.show()
        ssid = p[Dot11Elt].info.decode('UTF-8')
        bssid = str(p[Dot11].addr3).upper()
        channel = int(ord(p[Dot11Elt:3].info))
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

        # Check for encrypted networks
        if re.search("privacy", capability):
            priv = 'Y'
        else:
            priv = 'N'

        # Determine encryption type
        if p.getlayer(Dot11Elt, ID=48) is not None:
            enc = "WPA2"
        elif p.getlayer(Dot11Elt, ID=221) is not None and p.getlayer(Dot11Elt, ID=221).info.startswith(
                b'\x00P\xf2\x01\x01\x00'):
            enc = "WPA"
        else:
            if priv == 'Y':
                enc = "It's WEP"
            else:
                enc = "It's OPEN"

        if ssid == config['ssid']:
            currentAP = " {:>2d}   {:s}   {:s}  {:s}  {:s}".format(int(channel), priv, enc, bssid, ssid)

            if currentAP not in aps:    # This is an AP we haven't seen before
                aps.add(currentAP)
                if checkAP(ssid, bssid, channel, priv):
                    print(" GOOD ", currentAP)
                else:
                    print("  BAD ", currentAP)

                # pkt = p[Dot11Elt]
                # while isinstance(pkt, Dot11Elt):
                #     # intValue = ""
                #     # for myByte in pkt.info:
                #     #     if isinstance(myByte, bytes):
                #     #         intValue += str(ord(myByte))
                #     print(pkt.ID, " (", str(len(pkt.info)), ") ", pkt.info)
                #     pkt = pkt.payload




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

    print("\nSTATUS CHAN PRIV ENC        MAC               SSID")
    print("====================================================")
    # Start the sniffer
    sniff(iface=interface, prn=sniffAP, store=0)
