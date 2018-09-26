from scapy.all import *
import time

# macs = [
#  "00:27:E3:ED:D4:01",
#  "88:1D:FC:F3:E7:13",
#  "00:27:E3:EE:AA:43",
#  "18:8B:9D:6D:45:C1",
#  "00:27:E3:ED:94:82",
#  "00:27:E3:EE:A8:82",
#  "00:27:E3:AF:A2:C2",
#  "00:27:E3:EE:B9:01",
#  "A0:EC:F9:BF:84:C2",
#  "D4:6D:50:9E:6D:12"
# ]

macs = [
    "B0:39:56:0E:E8:14"
]

deauthAlertTimeout = 5  # How long (in seconds) minimum to wait between detected deauths to call it a new attack

clients = set()
deauthTimes = {}
deauthAlertTimes = {}

def noise_filter(addr1, addr2):
    # Broadcast, broadcast, IPv6mcast, spanning tree, spanning tree, multicast, broadcast
    ignore = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:'] # possibly add our detecting MAC address

    for i in ignore:
        if i in addr1 or i in addr2:
            return True

def packet_handler(pkt) :
    # if packet has 802.11 layer
    if pkt.haslayer(Dot11) and pkt.type == 2:
        # do your stuff here
        # types[pkt.type] = types[pkt.type]

        if noise_filter(pkt.addr1, pkt.addr2):
            return


        if pkt.addr1.upper() in macs and pkt.addr2.upper() not in clients:
            clients.add(pkt.addr2.upper())
            print("AP", " ", pkt.addr2.upper())
        elif pkt.addr2.upper() in macs and pkt.addr1.upper() not in clients:
            clients.add(pkt.addr1.upper())
            print(pkt.addr1.upper(), " ", "AP")
        # else:
        #     print(pkt.addr1.upper(), " ", pkt.addr2.upper())
    elif pkt.haslayer(Dot11Deauth):

        sourceMAC = str(pkt[Dot11].addr2).upper()
        if sourceMAC in deauthTimes:
            timeFromLastDeauth = time.time() - deauthTimes[sourceMAC]
            if timeFromLastDeauth < 5:
                if sourceMAC not in deauthAlertTimes or time.time() - deauthAlertTimes[sourceMAC] > deauthAlertTimeout:
                    print("Deauth detected from: ", sourceMAC)
                    # print(deauthTimes)
                    deauthAlertTimes[sourceMAC] = time.time()
        deauthTimes[sourceMAC] = time.time()

sniff(iface="wlan0mon", prn=packet_handler) #  filter="type Data"