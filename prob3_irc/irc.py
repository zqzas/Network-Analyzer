# Author : Hao Ma
try:
	from scapy.all import TCP, bind_layers, Packet, StrField, bind_layers, rdpcap
	import re
except:
	raise Exception("Cannot import library! Check regex and scapy.")



'''this is old function, after reconstruction and change to regex, this is no use
def _irc_dissect(obj, load):
	...
	#mainly string manipulations
'''

class IRC(Packet):
	name = "IRC"
	newline = '\n'

	fields_desc = [StrField("Prefix", None, fmt = "H"),
					StrField("Command", None, fmt = "H"),
					StrField("Parameter", None, fmt = "H"),
					StrField("Trailer", None, fmt = "H")]
	
	#According to RFC 2812, the commands of IRC is either letters or 3 digits number
	#See below:
	commands = ['PASS','NICK','USER','OPER','MODE','SERVICE','QUIT','SQUIT','JOIN','PART','MODE','TOPIC','NAMES','LIST',\
				 'INVITE','KICK','PRIVMSG','NOTICE','MOTD','LUSERS','VERSION','STATS','LINKS','TIME','CONNECT','TRACE',\
				 'ADMIN','INFO','SERVLIST','SQUERY','WHO','WHOIS','WHOWAS','KILL','PING','PONG','ERROR','AWAY','REHASH','DIE',\
				 'RESTART','SUMMON','USERS','WALLOPS','USERHOST','ISON'] \
				+['%03d' % d for d in xrange(1000)] #exact 3 digits number
	

	#Regular Expression of IRC messgage, can be deduced according to RFC 2811
	irc_regex = "^(:(?P<prefix>\S+) )?(?P<command>\S+)( (?!:)(?P<parameters>.+?))?( :(?P<trailer>.+))?$"

	def regex(self, msg):
		#only consider the first line
		msg = msg.split(IRC.newline)[0]

		match = re.search(IRC.irc_regex, msg)

		#return as groups
		return (match.group('prefix'), match.group('command'), match.group('parameters'), match.group('trailer'))

	def do_dissect(self, s):
        #split into lines
		if s.count('\r') > s.count('\n'):#check the line breaker
			IRC.newline = '\r'
		else:
			IRC.newline = '\n'

		ls = s.strip().split(IRC.newline)

        
        #do dissect recursively, because the format is same in every line:
		num = len(ls)
		try:
			#old approach: string manipulations 
			#_irc_dissect(self, ls[num - 1])

			#new approach: use regular expression to parse
			(prefix, command, parameters, trailer) = self.regex(ls[num - 1])
	
			self.setfieldval('Prefix', prefix)
			self.setfieldval('Command', command)
			self.setfieldval('Parameter', parameters)
			self.setfieldval('Trailer', trailer)
		except:
			raise Exception("Dissecting Error!")
        #if only one line:
		if num == 1:
			return ''
		for i in range(0, num - 1):
            #add these lines, recursively:
			self.underlayer.add_payload(IRC(ls[i]))

class IRCRequest(IRC):
	name = "IRC Request"

class IRCResponse(IRC):
	name = "IRC Response"

class IRCDetector(Packet):
#Dynamic Protocol Detection
	name = "IRC Detector"

	def guess_payload_class(self, payload):

		#to match the payload in the regular expression
		groups = IRC().regex(payload)
		command = groups[1] 

		
		if command != None:
			if command in IRC.commands: # to check if it's a irc command
				return IRC
		return Packet.guess_payload_class(self, payload) #return default guess

'''this is no use because I implemented the dynamic proto detection, so it's now independent from port number :-)
for port in IRC_Port:
	try:
		bind_layers(TCP, IRCRequest, dport = port)
		bind_layers(TCP, IRCResponse, sport = port)
	except:
		raise Exception("Scapy Binding Error!")
'''

try:
	bind_layers(TCP, IRCDetector) #independent from port number
except:
	raise Exception("Scapy Binding Error!")
	
    
if __name__ == '__main__':
	try:
		t = rdpcap('one_irc.pcap')
	except:
		raise Exception("Pcap Reading Error!")

	t.show()

	for pkt in t:
		print '=' * 70
		pkt.show()

    
