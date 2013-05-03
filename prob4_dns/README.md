Problem 4: Detect DNS Anomaly
===================

Write a DNS handler.

Test the pcap file: http://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=dns-remoteshell.pcap

The handler should understand the DNS anomaly and display the results.

Approach:
----
My approach is based on scapy.

My program could properly handle the 802.11 and LLC layer in the packets.

After decode 802.11 and LLC layer, the program is able to read tcp information in the payload.

And because my program binds the tcp.port 53 to my customized layer DNS\_Extend which inherits base layer Packet, it can detect the DNS Anomalies and store them in the fields of class DNS\_Extended.

###Note:
If a tcp's payload is empty or just padding, my program will not display it on the screen.

---

##Code:
```python
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
for p in pkts:
	#need to handle 802.11 and LLC protocol
	if p.payload.name == 'Raw':
		p.payload = Dot11(str(p.payload))
		m = p.payload.payload
		m.payload = LLC(m.wepdata)
	#When found DNS anomalies, output
	if p.haslayer(TCP) and p[TCP].payload.name == 'DNS_Extended':
		print '=' * 100
		print 'DNS Anomaly:\n', p.show()

```

## Output
```python
DNS Anomaly:
###[ Ethernet ]###
  dst       = 00:10:c6:30:6b:b3
  src       = 00:0e:35:78:0c:02
  type      = 0x2452
###[ 802.11 ]###
     subtype   = 0L
     type      = Data
     proto     = 0L
     FCfield   = to-DS+wep
     ID        = 513
     addr1     = 00:10:c6:30:6b:b3
     addr2     = 00:80:48:24:33:32
     addr3     = 00:0e:35:78:0c:02
     SC        = 896
     addr4     = None
###[ 802.11 WEP packet ]###
        iv        = '\xda\xfc\xf7'
        keyid     = 0
        wepdata   = '\xaa\xaa\x03\x00\x00\x00\x08\x00E\x00\x00\x80\x07\xcd@\x00@\x06\xafU\xc0\xa8\x01\x02\xc0\xa8\x01\x03\x005\x05t\xbd\x0f/\xed#\xc53\xc0P\x18\xff\xffN\x14\x00\x00Microsoft Windows XP [Version 5.1.2600]\r\n(C) Copyright 1985-2001 Microsoft Corp.\r\n\r\nC:\\>'
        icv       = 1629383609
###[ LLC ]###
           dsap      = 0xaa
           ssap      = 0xaa
           ctrl      = 3
###[ SNAP ]###
              OUI       = 0x0
              code      = 0x800
###[ IP ]###
                 version   = 4L
                 ihl       = 5L
                 tos       = 0x0
                 len       = 128
                 id        = 1997
                 flags     = DF
                 frag      = 0L
                 ttl       = 64
                 proto     = tcp
                 chksum    = 0xaf55
                 src       = 192.168.1.2
                 dst       = 192.168.1.3
                 \options   \
###[ TCP ]###
                    sport     = domain
                    dport     = dvl_activemail
                    seq       = 3171889133
                    ack       = 600126400
                    dataofs   = 5L
                    reserved  = 0L
                    flags     = PA
                    window    = 65535
                    chksum    = 0x4e14
                    urgptr    = 0
                    options   = []
###[ DNS_Extended ]###
                       DNS anomaly= 'Microsoft Windows XP [Version 5.1.2600]\r\n(C) Copyright 1985-2001 Microsoft Corp.\r\n\r\nC:\\>'
                       
...more
                       
```