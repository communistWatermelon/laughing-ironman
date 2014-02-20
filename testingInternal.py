'''
--------------------------------------------------------------------------------------------
--	SCRIPT:	    testingInternal.py
--
--	FUNCTIONS:  None
--
--	DATE:       February 19, 2014
--
--	DESIGNERS:  John Payment
--              Jake Miner
--
--	PROGRAMMER: Jake Miner
--                  
--
--	NOTES: This program tests the validity of the firewall rules from behind the firewall
-- 			It is to be run on the client behind the firewall. 
--			PLEASE SET THE FIREWALL IP
---------------------------------------------------------------------------------------------
'''
import os

firewallIP = "192.168.0.13"
clientIP   = "192.168.10.42" 
outgoingIP = "192.168.0.3"

#Can successfully complete a DNS lookup.
os.system("host google.com")

#Drop outgoing TCP packets connecting from port 0
os.system("hping " + outgoingIP + " -s 0 -p 22 -V")
os.system("hping " + outgoingIP + " -s 0 -p 80 -V")

#Drop outgoing UDP packets connecting from port 0
os.system("hping " + outgoingIP + " -s 0 -p 80 -2 -V")
os.system("hping " + outgoingIP + " -s 0 -p 22 -2 -V")


#Drop packets connecting to port 80 from ports between 0 and 1024
os.system("hping " + outgoingIP + " -p 80 -s 1022 -V")
os.system("hping " + outgoingIP + " -p 80 -s 2 -V")

#Drop packets with the SYN bit set which are trying to connect to high-number ports
os.system("hping " + outgoingIP + " -p 12252 -S -V")
os.system("hping " + outgoingIP + " -p 1025 -S -V")

#Drop incoming packets that are using telnet (TCP port 23)
os.system("hping " + outgoingIP + " -p 23 -S -V")
os.system("hping " + outgoingIP + " -p 23 -V")
os.system("hping " + outgoingIP + " -p 23 -s 23 -S -V")
os.system("hping " + outgoingIP + " -p 23 -s 23 -V")
os.system("hping " + outgoingIP + " -s 23 -S -V")
os.system("hping " + outgoingIP + " -s 23 -V")

#Drop all TCP packets with both the SYN and FIN bits set
os.system("hping " + outgoingIP + " -p 22 -S -F -V")
os.system("hping " + outgoingIP + " -p 80 -S -F -V")

#Can connect to an external http server
os.system("firefox linux.com")

#Can connect to a external HTTPS server
os.system("firefox google.com")

#Can connect to an external PC using SSH from inside.
os.system("ssh 192.168.0.3")

#Allowed ICMP Types are forwarded. 
os.system("ping google.com")
os.system("ping " + outgoingIP)

