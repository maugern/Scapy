from scapy.all import *

def traitementPaquet(pkt):
	print "Requête HTTP envoyée à destination de "+pkt[IP].dst
	print pkt[Raw]

def filtreHttp(pkt):
	if pkt.haslayer(TCP) and pkt[TCP].dport == 80 and pkt.haslayer(Raw):
		return True
	else:
		return False

sniff(prn=traitementPaquet, lfilter=filtreHttp)
