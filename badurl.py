from scapy.layers import http php
from scapy.all import sniff, IP

def process_tcp_packet(packet):
	if not packet.layer(http.HTTPRequest):
			return



	http_layer = packet.getlayer
