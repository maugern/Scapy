#! /usr/bin/env python
# arping2tex : arpings a network and outputs a LaTeX table as result
import sys
if len(sys.argv) != 2:
    print "Usage: arping2tex <net>\n eg: arping2tex 192.168.1.0/24"
    sys.exit(1)
from scapy import srp,Ether,ARP,conf
conf.verb=0
ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[1]),timeout=2)
print "\\begin{tabular}{|l|l|}"
print "\\hline"
print "MAC & IP\\\\"
print "\\hline"
for s,r in ans:
    print r.sprintf("%Ether.src% & %ARP.psrc%\\\\")
print "\\hline"
print "\end{tabular}"
