Problem 1: Force-Directed Graph
===================

By using wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=http.cap file, create a csv file. The format of the csv file shoud like the below:

###source,target,value

Source: source ip

Target: destination ip

####Value: I define this as the number of connections between source and target.

####For example :
"65.208.228.223,145.254.160.237,18" means:

there are exactly 18 connections from 65.208.228.223 to 145.254.160.237.

Approach:
----

Use rdpcap() in scapy to read pcap file.

And get IP layer of each packet.

Then count the number of connections between hosts. 

Finally, after carefully handling duplications, I store the connections in a csv file.


##CSV File:

###Note: 
#####This is a directed graph, so there might be two links between two hosts (in both directions).
```csv
source,target,value
65.208.228.223,145.254.160.237,18
145.254.160.237,65.208.228.223,16
145.253.2.203,145.254.160.237,1
216.239.59.99,145.254.160.237,4
145.254.160.237,145.253.2.203,1
145.254.160.237,216.239.59.99,3
```



###Code:
```python
#Author: Hao Ma

import csv
from scapy.all import Packet, rdpcap, IP


class Displayer:

	def readpcap(self, pcap):
		pktlist = rdpcap(pcap)
        #use dictionary to count the number of connections between hosts
		dic = {}
		for x in pktlist:
            #get IP larer in scapy way
			pkt = x[IP]
			pair = (pkt.src, pkt.dst)
			try:
				dic[pair] += 1
                #try if this pair has occured in dictionary
			except KeyError:
                #create new one
				dic[pair] = 1

		#write csv:
		with open('conn.csv', 'wb') as csvfile:
			writer = csv.writer(csvfile, delimiter=',')
			writer.writerow(['source', 'target', 'value'])
            #output the dictionary
			for pair in dic:
				writer.writerow([pair[0], pair[1], dic[pair]])
			
if __name__ == '__main__':
	Displayer().readpcap('http.pcap')
			               
```