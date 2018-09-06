#!/usr/bin/env python
import logging
# Silence Scapy IPv6 message at runtime
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
# import argparse
import datetime
import sys


# Keep track of unique mac addresses
mac_list = []

# Vendors
ven_dic = {}

verbose = True

# Interface to monitor. Once you have your wireless
# nic listening, make sure to replace the variable string
# with your listening wireless nic.
# EX: iwconfig #to find your wireless nic (eg: wlan1)
# EX: sudo airmon-ng start wlan1 (Or the wireless nic you saw in previous step)
# EX: iwconfig #to find out the name of the nic airmon created
interface = "mon0"

# Arguments
# parser = argparse.ArgumentParser()
# parser.add_argument("-V", "--verbose", help="different formatting and detailed output", action="store_true")
# args = parser.parse_args()



# Read in vendors and add to ven_dic
# with open("vendors.txt") as vendors:
#     for line in vendors:
#         join_line = " ".join(line.split())
#         ven_mac = join_line.split(" ")[0]
#         ven_name = join_line.split(" ")[1]
#         ven_dic[ven_mac] = ven_name

# Function to print if access point is detected

def AccessPointPrint(mac, ssid):
    # Check to see if we know the vendor
    if mac[0:8].upper() in ven_dic.keys():
        vendor = ven_dic[mac[0:8].upper()]
    else:
        vendor = "unknown"

    # If verbose was used, print out the format below
    if verbose:
        print("-" * 146 + "\n")
        print("TIME    :", datetime.datetime.now())
        print("MAC     :", mac)
        print("TYPE    :", "Access Point")
        print("SSID    :", ssid)
        print("CHIPSET :", vendor)
        # I recommend customizing the note below to your liking.
        # print
        # "NOTE    : This is an access point that is broadcasting its wireless SSID for client connection. "

    # Else print the default format
    # else:
    #     print
    #     colored("* I SEE YOU! * ", "red", attrs=["bold"]) + "%s (%s)" % (mac, vendor), "as an", \
    #     colored("ACCESS POINT", "yellow", attrs=["bold"]), "for SSID:", colored(ssid, "green", attrs=["bold"])


# Function to print if client probe is detected
def ProbePrint(mac, ssid):
    # Check to see if we know the vendor
    if mac[0:8].upper() in ven_dic.keys():
        vendor = ven_dic[mac[0:8].upper()]
    else:
        vendor = "unknown"

    # If verbose was used, print out the format below
    if verbose:
        print("-" * 146 + "\n")
        print("TIME    :", datetime.datetime.now())
        print("MAC     :", mac)
        print("TYPE    :", "Probing")
        print("SSID    :", ssid)
        print
        "CHIPSET :", vendor
        # I recommend customizing the note below to your liking.
        print
        'NOTE    : '  '''This traffic is from an asset attempting to connect to a wireless network it has seen before.
          The wireless packets are able to be intercepted and parsed to reveal a network the device trusts. An "Evil-Twin"
          attack can occur where a malicious actor creates an access point with the same SSID name to intercept credentials.'''

    # Else print the default format
    else:
        print
        colored("* I SEE YOU! * ", "red", attrs=["bold"]) + "%s (%s)" % (mac, vendor), \
        colored("PROBING", "yellow", attrs=["bold"]), "for SSID:", colored(ssid, "green", attrs=["bold"])

def PacketAnalyzer(pkt):

    # Check to make sure we got an 802.11 packet
    if pkt.haslayer(Dot11):

        # Check to see if it's an access point beacon
        if pkt.type == 0 and pkt.subtype == 8:
            # Check to see if we have seen the MAC address before, if not, continue with printing
            if pkt.addr2 not in mac_list:
                mac_list.append(pkt.addr2)
                AccessPointPrint(pkt.addr2, pkt.info)

        # Check to see if it's a device probing for networks
        if pkt.haslayer(Dot11ProbeReq):
            # Check to see if we have seen the MAC address before, if not, continue with printing
            if pkt.addr2 not in mac_list:
                mac_list.append(pkt.addr2)
                # Make sure SSID is not blank
                if pkt.info != "":
                    ProbePrint(pkt.addr2, pkt.info)

sniff(iface=interface, prn=PacketAnalyzer, store=0)








