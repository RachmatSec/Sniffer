#!/usr/bin/python
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import socket
import datetime
import os
import time

def memonitor_jaringan_untuk_versi_visualisasi(pkt):

    # Mendeklarasikan variabel untuk menentukan waktu merekam sekarang
    waktu = datetime.datetime.now()

    # Merekam paket TCP
    if pkt.haslayer(TCP):

        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print(str("[") + str(waktu) + str("]") + "  " + "TCP-IN:{}".format(len(pkt[TCP])) + " Bytes" + "  " + "SRC-MAC: " + str(pkt.src) + "  " + "DST-MAC: " + str(pkt.dst) + "  " + "SRC-PORT: " + str(pkt.sport) + "  " + "DST-PORT: " + str(pkt.dport) + "  " + "SRC-IP: " + str(pkt[IP].src) + "  " + "DST-IP: " + str(pkt[IP].dst))
            
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print(str("[") + str(waktu) + str("]") + " " + "TCP-OUT:{}".format(len(pkt[TCP])) + " Bytes" + "  " + "SRC-MAC: " + str(pkt.src) + "  " + "DST-MAC: " + str(pkt.dst) + "  " + "SRC-PORT: " + str(pkt.sport) + "  " "DST-PORT: " + str(pkt.dport) + "  " + "SRC-IP: " + str(pkt[IP].src) + "  " + "DST-IP: " + str(pkt[IP].dst))
        
    # Merekam paket UDP
    if pkt.haslayer(UDP):
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print(str("[") + str(waktu) + str("]") + "  " + "TCP-OUT:  {}".format(len(pkt[UDP])) + " Bytes" + "  " + "SRC-MAC: " + str(pkt.src) + "  " + "DST-MAC: " + str(pkt.dst) + "  " + "SRC-PORT: " + str(pkt.sport) + "  " + "DST-PORT: " + str(pkt.dport) + "  " + "SRC-IP: " + str(pkt[IP].src) + "  " + "DST-IP: " + str(pkt[IP].dst))

        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print(str("[") + str(waktu) + str("]") + "  " + "UDP-IN:   {}".format(len(pkt[UDP])) + " Bytes" + "  " + "SRC-MAC: " + str(pkt.src) + "  " + "DST-MAC: " + str(pkt.dst) + "  " + "SRC-PORT: " + str(pkt.sport) + "  " + "DST-PORT: " + str(pkt.dport) + "  " + "SRC-IP: " + str(pkt[IP].src) + "  " + "DST-IP: " + str(pkt[IP].dst))

    # Merekam paket ICMP
    if pkt.haslayer(ICMP):
        if socket.gethostbyname(socket.gethostname()) == pkt[IP].src:
            print(str("[") + str(waktu) + str("]") + "  " + "ICMP-OUT: {}".format(len(pkt[ICMP])) + " Bytes" + "  " + "IP-Version: " + str(pkt[IP].version) + "  " * 1 + " SRC-MAC: " + str(pkt.src) + "  " + "DST-MAC: " + str(pkt.dst) + "  " + "SRC-IP: " + str(pkt[IP].src) + "  " + "DST-IP: " + str(pkt[IP].dst))

        if socket.gethostbyname(socket.gethostname()) == pkt[IP].dst:
            print(str("[") + str(waktu) + str("]") + "  " + "ICMP-IN:  {}".format(len(pkt[ICMP])) + " Bytes" + "  " + "IP-Version: " + str(pkt[IP].version) + "  " * 1 + " SRC-MAC: " + str(pkt.src) + "  " + "DST-MAC: " + str(pkt.dst) + "  " + "SRC-IP: " + str(pkt[IP].src) + "  " + "DST-IP: " + str(pkt[IP].dst))

# Menjalankan fungsi
if __name__ == '__main__':
    sniff(prn = memonitor_jaringan_untuk_versi_visualisasi)