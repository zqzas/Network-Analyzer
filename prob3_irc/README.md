Problem 3:  IRC Parser
===================

Write an IRC handler that reads a pcap and understands it and parse its information. The handler should be a class and the usage example should be demostrated with the pcap sample.


My parser is based on Scapy, using bind_layers() to extend the protocol:

New Approach:
---
I have reconstructed the parser and add three more things to make my code more beautiful:

1. Regular Expression Based Parsing
2. Dynamic Protocol Detection (Independent from port number)
3. Error Handling
4. Unit Test

###1. Regular Expression Based Parsing

I've spent some time on reading RFC 2812 to find more precise patterns of IRC messages and collected the keywords might appears in IRC. 

And finally got the regular expression that can match the messages nicely:

```python
irc_regex = 
"^(:(?P<prefix>\S+) )?(?P<command>\S+)( (?!:)(?P<parameters>.+?))?( :(?P<trailer>.+))?$"
```
Inspired by and thanks to http://news.anarchy46.net/2012/01/irc-message-regex.html.


Doing regular expression can help me get rid of string manipulations which is my previous method. And achieve the code more clean  :-)

---

Here is the IRC keywords that I summarized according to RFC 2812:

```python
commands = 
['PASS','NICK','USER','OPER','MODE','SERVICE','QUIT','SQUIT','JOIN','PART','MODE','TOPIC','NAMES','LIST',\		 'INVITE','KICK','PRIVMSG','NOTICE','MOTD','LUSERS','VERSION','STATS','LINKS','TIME','CONNECT','TRACE',\
'ADMIN','INFO','SERVLIST','SQUERY','WHO','WHOIS','WHOWAS','KILL','PING','PONG','ERROR','AWAY','REHASH','DIE',\
'RESTART','SUMMON','USERS','WALLOPS','USERHOST','ISON'] \
+
['%03d' % d for d in xrange(1000)] #exact 3 digits number
```
```python
def regex(self, msg):
		#only consider the first line(message)
		msg = msg.split(IRC.newline)[0]

		match = re.search(IRC.irc_regex, msg)

		#return as groups
		return (match.group('prefix'), match.group('command'), match.group('parameters'), match.group('trailer'))
```

---

###2. Dynamic Protocol Detection (Independent from port number):
I am so excited that this is my first implementation of dynamic protocol detection. And my method is :

1. I get the payload and break into single messages (lines).

2. Pass the message to regular expression (regex) function and get the groups into prefix, command, parameters and trailer. 

3. If successfully parsed by regex, then check the command whether it is among the keywords of IRC that I listed above.

4. If keyword matches, then return IRC as successful detection; Otherwise, return the default guess of Scapy's Packet class.

```python
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

```
---

###3. Error Handling:
Try and raise exception when necessary.

In addition, I also made a new approach to enable the line breaker with more flexibility. 
Now it supports \n or \r or \r\n to seperate lines.

###4. Unit Test:

To test the code with small data set, medium data set, and a larger set. 

Moreover, I also tested other protocol like DNS to check the compatibility of my code, the protocol detection works fine, which won't affect the default protocol detection of Scapy after I make extensions based on Scapy.

For details you may refer to unittest_irc.py and test results in the repository.



---------------
----------

Old Approach:
---


##Class Structure:
Due to the similarity between IRC response and request, I define a base class IRC which has common fields "Prefix", "Command", "Parameter" and "Trailer".

And IRCRequest and IRCResponse inherit IRC.


```python
#Author: Hao Ma

class IRC(Packet):
	name = "IRC"
	fields_desc = [StrField("Prefix", None, fmt = "H"),
					StrField("Command", None, fmt = "H"),
					StrField("Parameter", None, fmt = "H"),
					StrField("Trailer", None, fmt = "H")]

	def do_dissect(self, s):
        #split into lines
		ls = s.strip().split("\r\n")
        
        #do dissect recursively, 
        #because the format is same in every line:        
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
```
##IRC Parser:
This parser is called by "do_dissect()" in class IRC:

###IRC specification:
The message format is:




```
:<prefix> <command> <params> :<trailing>
```


And here is an example:
```
:CalebDelnay!calebd@localhost PRIVMSG #mychannel :Hello everyone!
```

###Note: 
Every message occupies a single line.

Messages are normally seperated by "\r\n" in a packet's payload. 

And every line's format is same, so I could do it recursively to handle all the lines, you may see do_dissect() in class IRC above.



##Parser Code:
```python
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

```
## Example Output
```python
======================================================================
###[ Ethernet ]###
  dst       = 00:16:e3:19:27:15
  src       = 00:04:76:96:7b:da
  type      = 0x800
###[ IP ]###
     version   = 4L
     ihl       = 5L
     tos       = 0x0
     len       = 68
     id        = 30451
     flags     = DF
     frag      = 0L
     ttl       = 64
     proto     = tcp
     chksum    = 0x56d7
     src       = 192.168.1.2
     dst       = 212.204.214.114
     \options   \
###[ TCP ]###
        sport     = amt_blc_port
        dport     = 6667
        seq       = 1304973067
        ack       = 1425084880
        dataofs   = 8L
        reserved  = 0L
        flags     = PA
        window    = 8011
        chksum    = 0x6d20
        urgptr    = 0
        options   = [('NOP', None), ('NOP', None), ('Timestamp', (14231265, 2196038037))]
###[ IRC Request ]###
           Prefix    = None
           Command   = 'WHO'
           Parameter = '#rokymotion'
           Trailer   = None
======================================================================
###[ Ethernet ]###
  dst       = 00:04:76:96:7b:da
  src       = 00:16:e3:19:27:15
  type      = 0x800
###[ IP ]###
     version   = 4L
     ihl       = 5L
     tos       = 0x0
     len       = 1076
     id        = 21520
     flags     = DF
     frag      = 0L
     ttl       = 46
     proto     = tcp
     chksum    = 0x87ca
     src       = 212.204.214.114
     dst       = 192.168.1.2
     \options   \
###[ TCP ]###
        sport     = 6667
        dport     = amt_blc_port
        seq       = 1425084880
        ack       = 1304973083
        dataofs   = 8L
        reserved  = 0L
        flags     = PA
        window    = 57920
        chksum    = 0x7c6e
        urgptr    = 0
        options   = [('NOP', None), ('NOP', None), ('Timestamp', (2196038119, 14231265))]
###[ IRC ]###
           Prefix    = ':sterling.freenode.net'
           Command   = '352'
           Parameter = 'vmlemon #rokymotion n=lando pool-71-121-181-242.sttlwa.dsl-w.verizon.net irc.freenode.net land0 H '
           Trailer   = ':0 gaim'
###[ IRC ]###
              Prefix    = ':sterling.freenode.net'
              Command   = '352'
              Parameter = 'vmlemon #rokymotion n=insane amarok/bot/insanity irc.freenode.net insanity H '
              Trailer   = ':0 Ruby bot. (c) Tom Gilbert'
###[ IRC ]###
                 Prefix    = ':sterling.freenode.net'
                 Command   = '352'
                 Parameter = 'vmlemon #rokymotion n=oggb4mp3 amarok/livecd/oggb4mp3 irc.freenode.net oggb4mp3 H '
                 Trailer   = ':0 oggb4mp3'
###[ IRC ]###
                    Prefix    = ':sterling.freenode.net'
                    Command   = '352'
                    Parameter = 'vmlemon #rokymotion n=tyson host86-128-245-115.range86-128.btcentralplus.com irc.freenode.net vmlemon H '
                    Trailer   = ':0 Tyson Key'
###[ IRC ]###
                       Prefix    = ':sterling.freenode.net'
                       Command   = '352'
                       Parameter = 'vmlemon #rokymotion n=jefferai amarok/developer/mitchell irc.freenode.net jefferai H '
                       Trailer   = ':0 Jeff Mitchell'
###[ IRC ]###
                          Prefix    = ':sterling.freenode.net'
                          Command   = '352'
                          Parameter = 'vmlemon #rokymotion i=Hydrogen perdition.campus.alfred.edu irc.freenode.net Hydrogen H '
                          Trailer   = ':0 Dan'
###[ IRC ]###
                             Prefix    = ':sterling.freenode.net'
                             Command   = '352'
                             Parameter = 'vmlemon #rokymotion n=xpert port-87-234-134-49.dynamic.qsc.de irc.freenode.net [Xpert] H '
                             Trailer   = ':0 xpert'
###[ IRC Response ]###
                                Prefix    = ':sterling.freenode.net'
                                Command   = '352'
                                Parameter = 'vmlemon #rokymotion n=paulc amarok/developer/foreboy irc.freenode.net foreboy H '
                                Trailer   = ':0 P'
                                
...more
                       
```
