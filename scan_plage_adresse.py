#! /usr/bin/python
from scapy.all import *

rang = '192.168.1.1-15'
rep,non_rep = sr( IP(dst=rang) / ICMP() , timeout=0.5 )
for elem in rep : # elem représente un couple (paquet émis, paquet reçu)
	if elem[1].type == 0 : # 0 <=> echo-reply
		print elem[1].src + ' a renvoye un echo-reply '
