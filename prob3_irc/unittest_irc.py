import sys
import unittest
from scapy.all import rdpcap
from irc import *

class TestIRC(unittest.TestCase):
	def setUp(self):
		self.inputFile = ''
		self.outputFile = ''
	
	def doTest(self):
		#redirect stdout to file
		sys.stdout = open(self.outputFile, 'w')
		pkts = rdpcap(self.inputFile)
		pkts.show()
		print '\n', '-' * 20, 'Packets Details:', '\n'
		for p in pkts:
			p.show()
			print '=' * 70

	def test_smaller_size(self):
		self.inputFile = 'a_few_irc.pcap'
		self.outputFile = 'test_results/results_smaller.txt'
		self.doTest()
	

	def test_medium_size(self):
		self.inputFile = 'medium_irc.pcap'
		self.outputFile = 'test_results/results_medium.txt'
		self.doTest()
		
	def test_larger_size(self):
		self.inputFile = 'a_larger_irc.pcap'
		self.outputFile = 'test_results/results_larger.txt'
		self.doTest()



if __name__ == '__main__':
	unittest.main()
