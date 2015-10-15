#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-

from scapy.all import *
temp=0

ans,unans=srloop(IP(dst="195.221.189.158")/TCP(dport=80,flags="S"),count=10)
for s,r in ans:
	temp=r[TCP].seq-temp
	print str(r[TCP].seq)+"\t+"+str(temp)

load_module("nmap")
conf.nmap_base
nmap_fp("195.221.189.158",oport=443,cport=1)
