#Author: Hao Ma

from scapy.all import *


class DNS_Extended(Packet):
	name = "DNS_Extended"
	fields_desc = [StrField("DNS anomaly", None, fmt = "H")]

	def do_dissect(self, payload):
		self.setfieldval("DNS anomaly", payload)
		return ''

			
#bind the tcp.port 53 to DNS_Extended
bind_layers(TCP, DNS_Extended, sport = 53)
bind_layers(TCP, DNS_Extended, dport = 53)

pkts = rdpcap('dns-remoteshell.pcap')
index = 0
for p in pkts:
	index += 1
	#need to handle 802.11 and LLC protocol
	if p.payload.name == 'Raw':
		p.payload = Dot11(str(p.payload))
		m = p.payload.payload
		m.payload = LLC(m.wepdata)
	if p.haslayer(TCP) and p[TCP].payload.name == 'DNS_Extended':
		print '=' * 100
		print 'DNS Anomaly: Frame %d\n'%(index), p.show()

