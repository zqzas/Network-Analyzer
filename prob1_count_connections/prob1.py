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
                #try if the pair hasn't occured in dictionary
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
			
			


		



	




