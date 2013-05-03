# Author : Hao Ma



from scapy.all import TCP, bind_layers, Packet, StrField, bind_layers, rdpcap


def _irc_dissect(obj, load):
	s = load[:]
    #get prefix (Optional):
	if s[0] == ':':
		space = s.find(' ')
		if space == -1:	
			raise Exception("Packet Error: Invalid Message")
		obj.setfieldval('Prefix', s[ : space])
		s = s[space + 1 : ]
	space = s.find(' ')
    #get command:
	if space == -1:
		obj.setfieldval('Command', s.strip())
		return ''
	obj.setfieldval('Command', s[ : space])
	s = s[space + 1 :]
    #get parameter:
	colon = s.find(':')
	if colon == -1 :
		obj.setfieldval('Parameter', s.strip())
		return ''
	obj.setfieldval('Parameter', s[ : colon])
    #get trailer:
	next_colon = s[colon + 1 :].find(':')
	if next_colon == -1:
		obj.setfieldval('Trailer', s[colon : ].strip())
		return ''
	obj.setfieldval('Trailer', s[colon: colon + 1 + next_colon])
	return s[colon + 1 + next_colon : ]

class IRC(Packet):
	name = "IRC"
	fields_desc = [StrField("Prefix", None, fmt = "H"),
					StrField("Command", None, fmt = "H"),
					StrField("Parameter", None, fmt = "H"),
					StrField("Trailer", None, fmt = "H")]

	def do_dissect(self, s):
        #split into lines
		ls = s.strip().split("\r\n")
        
        #do dissect recursively, because the format is same in every line:
		num = len(ls)
		_irc_dissect(self, ls[num - 1])
        #if only one line:
		if num == 1:
			return ''
		for i in range(0, num - 1):
            #add these lines:
			self.underlayer.add_payload(IRC(ls[i]))


class IRCRequest(IRC):
	name = "IRC Request"

class IRCResponse(IRC):
	name = "IRC Response"


IRC_Port = range(6660, 6669) + [7000, 194, 6697] 

for port in IRC_Port:
    bind_layers(TCP, IRCRequest, dport = port)
    bind_layers(TCP, IRCResponse, sport = port)
   
    
if __name__ == '__main__':
    t = rdpcap('irc.pcap')
    for pkt in t:
    	print '=' * 70
        pkt.show()

    
