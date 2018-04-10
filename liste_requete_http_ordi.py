from scapy.all import *

def traitementPaquet(pkt):
	print "Requête HTTP envoyée à destination de "+pkt[IP].dst
	print pkt[Raw]

def filtreHttp(pkt):
	return pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw)
		
sniff(prn=traitementPaquet, lfilter=filtreHttp)
