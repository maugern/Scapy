#!/usr/bin/env python
 
import sys
from scapy import *
 
target = sys.argv[1]
fl = 22
 
while (fl<=25):
   p=sr1(IP(dst=target)/TCP(dport=fl, flags="S"),retry=0,timeout=1)
   if p:
     print "\n Le port " + str(fl) + " TCP est ouvert sur " + str(target) + "\n"
   else:
     print "\n Le port " + str(fl) + " TCP n'est pas ouvert sur " + str(target) + "\n"
   fl = fl + 1
