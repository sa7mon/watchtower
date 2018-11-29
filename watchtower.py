#!/usr/bin/env python

import sys, os, signal
from multiprocessing import Process
import json
import requests
from scapy.all import *
import argparse
import csv


parser = argparse.ArgumentParser(description="WatchTower - Detect Rogue APs", prog='watchtower')
parser.add_argument('--tune', required=False, dest='tune', action='store_true',
                    help='Collect samples of average signal strength from each AP')
parser.add_argument('adapter', help='Name of wireless adapter in promiscuous mode')

parser.set_defaults(tune=False)

args = parser.parse_args()

#####################
#
#  Global Variables
#
#####################

interface = ''  # monitor interface
aps = set()  # dictionary to store unique APs
clients = set()
apSignals = {}  # For --tune mode
deauthTimes = {}
deauthAlertTimes = {}
deauthAlertTimeout = 5  # How long (in seconds) minimum to wait between detected deauths to call it a new attack
macVendors = {}


def checkAP(ap_mac, ap_channel, ap_enc, ap_cipher, ap_auth, ap_strength):
    if config['checks']['checkMAC']:
        if ap_mac.upper() not in config['macs']:
            return False

    if config['checks']['checkChannel']:
        if ap_channel != config['channel']:
            print("Bad channel: ", ap_channel, " ", config['channel'])
            return False

    if config['checks']['checkEncryption']:
        if ap_enc != config['encryption']:
            print("Bad encryption: ", ap_enc, " ", config['encryption'])
            return False

    if config['checks']['checkCipher']:
        if ap_cipher != config['cipher']:
            print("Bad cipher: ", ap_cipher, " ", config['cipher'])
            return False

    if config['checks']['checkAuthentication']:
        if ap_auth != config['authentication']:
            print("Bad auth: ", ap_auth, " - ", config['authentication'])
            return False

    if config['checks']['checkStrength']:
        upper = config['signalStrength'] + config['strengthVariance']
        lower = config['signalStrength'] - config['strengthVariance']
        if ap_strength < lower or ap_strength > upper:
            return False

    return True


def noise_filter(addr1, addr2):
    # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:'] # possibly add our detecting MAC address

    for i in ignore:
        if i in addr1 or i in addr2:
            return True


def getWPA2info(pkt):
    # pkt = p.getlayer(Dot11Elt, ID=48)
    # print(pkt.ID, len(pkt.info), pkt.info)

    # Array slices don't include end index so add 1

    # 00-0F-AC-01 WEP40
    # 00-0F-AC-05 WEP104
    # 00-0F-AC-04 CCMP
    # 00-0F-AC-02 TKIP

    # OUI = [2:4]
    # groupCipherOUI = pkt.info[2:5]
    groupCipherOUI = pkt.group_cipher_suite.oui

    # Group Cipher Type = [5]
    # 1 = WEP40, 2 = TKIP, 4 = CCMP, 5 = WEP104
    # groupCipherType = pkt.info[5]
    groupCipherType = pkt.group_cipher_suite.cipher

    if groupCipherType == 1:
        cipher = "WEP40"
    elif groupCipherType == 2:
        cipher = "TKIP"
    elif groupCipherType == 4:
        cipher = "CCMP"
    elif groupCipherType == 5:
        cipher = "WEP104"
    else:
        cipher = "???"

    # Pairwise Cipher Count = [6:7]
    # pairwiseCipherCount = pkt.info[6]

    # PairwiseKey Cipher List (array?) = [8:11]
    # pairwiseCipherOUI =

    # AuthKey Mngmnt Count = [12:13]
    # authKeyMgmtCount = pkt.info[12]
    authKeyMgmtCount = pkt.nb_akm_suites

    # AuthKey Mngmnt Suite List = [14:17]
    # 00-0f-ac-02  PSK
    # 00-0f-ac-01  802.1x (EAP)
    # authKeyMgmtSuite = pkt.info[14:18]

    if pkt.akm_suites[0].suite == 2:
        auth = "PSK"
        authKeyMgmtSuite = b'\x00\x0f\xac\x02'
    elif pkt.akm_suites[0].suite == 1:
        auth = "EAP"
        authKeyMgmtSuite = b'\x00\x0f\xac\x01'
    elif pkt.akm_suites[0].suite == 0:
        auth = "RESERVED"
        authKeyMgmtSuite = "???"
    else:
        auth = "???"
        authKeyMgmtSuite = "???"


    # DEBUG
    if cipher == '???' or auth == '???':
        print("Unknown cipher or auth.")

    return {
        "groupCipherOUI": groupCipherOUI,
        "groupCipherType": groupCipherType,
        "cipher": cipher,
        "authKeyMgmtCount": authKeyMgmtCount,
        "authKeyMgmtSuite": authKeyMgmtSuite,
        "auth": auth
    }


def sendSlackNotification(message):
    response = requests.post(
        config['slackWebhook'], json={"text":message},
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code != 200:
        raise ValueError(
            'Request to slack returned an error %s, the response is:\n%s'
            % (response.status_code, response.text)
        )


def sniffAP(pkt):

    # Look for clients of our network
    if pkt.haslayer(Dot11) and pkt.type == 2:
        if noise_filter(pkt.addr1, pkt.addr2):
            return

        if pkt.addr1.upper() in config['macs'] and pkt.addr2.upper() not in clients:
            clients.add(pkt.addr2.upper())
        elif pkt.addr2.upper() in config['macs'] and pkt.addr1.upper() not in clients:
            clients.add(pkt.addr1.upper())

    # Watch for deauth-ing of our clients
    elif pkt.haslayer(Dot11Deauth):

        sourceMAC = str(pkt[Dot11].addr2).upper()

        if sourceMAC not in clients:  # We only care about our AP and clients
            return

        if sourceMAC in deauthTimes:
            timeFromLastDeauth = time.time() - deauthTimes[sourceMAC]
            if timeFromLastDeauth < 5:
                if sourceMAC not in deauthAlertTimes or time.time() - deauthAlertTimes[sourceMAC] > deauthAlertTimeout:
                    print("Deauth detected! Targeted client: " + sourceMAC)
                    if config['sendSlackNotify']:
                        sendSlackNotification(":rotating_light: Deauth attack detected! Targeted client: " + sourceMAC)

                    deauthAlertTimes[sourceMAC] = time.time()
        deauthTimes[sourceMAC] = time.time()


    # process unique sniffed Beacons and ProbeResponses.
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        if pkt.haslayer(Dot11FCS):
            bssid = str(pkt[Dot11FCS].addr3).upper()
        else:
            bssid = str(pkt[Dot11].addr3).upper()
        ssid = pkt[Dot11Elt].info.decode('UTF-8')
        channel = int(ord(pkt[Dot11Elt:3].info))
        capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                    {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        strength = pkt[RadioTap].dBm_AntSignal

        # Check for encrypted networks
        if re.search("privacy", capability):
            priv = 'Y'
        else:
            priv = 'N'

        # Determine encryption type
        if pkt.getlayer(Dot11Elt, ID=48) is not None:
            enc = "WPA2"
        elif pkt.getlayer(Dot11Elt, ID=221) is not None and pkt.getlayer(Dot11Elt, ID=221).info.startswith(
                b'\x00P\xf2\x01\x01\x00'):
            enc = "WPA"
        else:
            if priv == 'Y':
                enc = "WEP"
            else:
                enc = "OPEN"

        if ssid == config['ssid']:
            if enc == "WPA2":
                apInfo = getWPA2info(pkt.getlayer(Dot11Elt, ID=48))
            else:
                apInfo = {}

            currentAP = "{:>2d}   {:s}   {:s}  {:s}    {:s}  {:s}  {:s}".format(
                int(channel), priv, enc, apInfo["cipher"], apInfo["auth"], bssid, ssid)

            if currentAP not in aps:    # This is an AP we haven't seen before
                aps.add(currentAP)
                currentAP = "{:>2d}   {:s}   {:s}  {:s}    {:s}  {:s}  {:s}  {:s}".format(
                    int(channel), priv, enc, apInfo["cipher"], apInfo["auth"], str(strength), bssid, ssid)
                if checkAP(bssid, channel, enc, apInfo["cipher"], apInfo["auth"], strength):
                    print("[Good AP] ", currentAP)
                else:
                    print("[Bad  AP] ", currentAP)
                    vendor = macVendors[bssid[0:8].replace(':', '')]
                    print("[Bad  AP] Manufacturer: ", vendor)
                    if config['sendSlackNotify']:
                        sendSlackNotification(":rotating_light: Rogue AP detected! :rotating_light: \n *Channel*: " + str(int(channel)) +
                                              "\n *Privacy*: " + priv +
                                              "\n *Encryption*: " + enc +
                                              "\n *Cipher*: " + apInfo['cipher'] +
                                              "\n *Authentication*: " + apInfo["auth"] +
                                              "\n *MAC*: " + bssid +
                                              "\n *SSID*: " + ssid +
                                              "\n *Vendor*: " + vendor)


def tune(pkt):
    bssid, ssid, channel, strength = '', '', '', ''

    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        if pkt.haslayer(Dot11FCS):
            bssid = str(pkt[Dot11FCS].addr3).upper()
        else:
            bssid = str(pkt[Dot11].addr3).upper()
        ssid = pkt[Dot11Elt].info.decode('UTF-8')
        channel = int(ord(pkt[Dot11Elt:3].info))
        strength = pkt[RadioTap].dBm_AntSignal
    if bssid not in config['macs']:
        return

    if strength != '':
        # print(type(strength), strength)
        # Check if AP already has signal measurement
        if bssid in apSignals:
            # https://math.stackexchange.com/questions/106313/regular-average-calculated-accumulatively

            apSignals[bssid]['count'] += 1
            old_avg = apSignals[bssid]['avgStrength']
            new_avg = ( (old_avg * (apSignals[bssid]['count']-1)) + strength ) / apSignals[bssid]['count']
            new_avg = int(round(new_avg))
            apSignals[bssid]['avgStrength'] = new_avg
            if old_avg != new_avg:
                print('Avg for', bssid, 'changed to: ', str(new_avg))
        else:
            apSignals[bssid] = {}
            apSignals[bssid]['count'] = 0
            apSignals[bssid]['avgStrength'] = 0


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
    # p.terminate()
    # p.join()

    sys.exit(0)


if __name__ == "__main__":

    with open('config.json') as f:
        config = json.load(f)

    with open('oui.csv') as csvfile:
        macreader = csv.reader(csvfile, delimiter=',', quotechar='"')
        i = 0
        for row in macreader:
            macVendors[row[1]] = row[2]

    interface = args.adapter

    if config['checks']['checkChannel']:
        # Start the channel hopper
        print("[*] Starting channel hopper process...")
        p = Process(target=channel_hopper)
        p.start()
    else:
        # Change adapter channel to expected channel
        print("[*] Locking adapter to channel", str(config['channel']))
        os.system("iw dev %s set channel %d" % (args.adapter, config['channel']))

    # Capture CTRL-C
    signal.signal(signal.SIGINT, signal_handler)

    # Start the sniffer
    if args.tune:
        print("[*] Starting tuning sniff...\n")
        sniff(iface=args.adapter, prn=tune, store=0)
    else:
        print("[*] Starting regular sniff...\n")
        sniff(iface=args.adapter, prn=sniffAP, store=0)
