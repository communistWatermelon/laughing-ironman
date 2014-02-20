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
--	NOTES: This program tests the validity of the firewall rules from outside the firewall
-- 			It is to be run on the network outside the firewall. 
--			PLEASE SET THE FIREWALL IP
---------------------------------------------------------------------------------------------
'''
import os

firewallIP = "192.168.0.13"
clientIP   = "192.168.10.42" 

#Drop All packets with a destination address of the firewall machine that arrive from outside. 
os.system("hping " + firewallIP + " -S -V")
os.system("hping " + firewallIP + " -p 22 -V")
os.system("hping " + firewallIP + " -p 80 -V")
os.system("hping " + firewallIP + " -p 443 -V")

#Drop all packets with ACK bit set which arrive from outside and are using non-allowed ports.
os.system("hping " + clientIP + " -p 12332 -S -V")
os.system("hping " + clientIP + " -p 12332 -V")

#Drop all Stateless packets.
os.system("hping " + clientIP + " -p 80 -V")
os.system("hping " + clientIP + " -p 22 -V")
os.system("hping " + clientIP + " -p 33 -V")

#Drop all packets arriving from outside but with the source address of an interior machine.
os.system("hping " + clientIP + " -a 192.168.10.12 -p 22 -S -V")
os.system("hping " + clientIP + " -a 192.168.10.23 -p 22 -V")
os.system("hping " + clientIP + " -a 192.168.10.5 -p 80 -S -V")

#Drop incoming TCP packets connecting from port 0
os.system("hping " + clientIP + " -s 0 -p 22 -V")
os.system("hping " + clientIP + " -s 0 -p 80 -V")

#Drop incoming UDP packets connecting from port 0
os.system("hping " + clientIP + " -s 0 -p 80 -2 -V")
os.system("hping " + clientIP + " -s 0 -p 22 -2 -V")

#Drop packets connecting to port 80 from ports between 0 and 1024
os.system("hping " + clientIP + " -p 80 -s 1022 -V")
os.system("hping " + clientIP + " -p 80 -s 2 -V")

#Drop packets with the SYN bit set which are trying to connect to high-number ports
os.system("hping " + clientIP + " -p 12252 -S -V")
os.system("hping " + clientIP + " -p 1025 -S -V")

#Drop outgoing packets that are using telnet (TCP port 23)
os.system("hping " + clientIP + " -p 23 -S -V")
os.system("hping " + clientIP + " -p 23 -V")
os.system("hping " + clientIP + " -p 23 -s 23 -S -V")
os.system("hping " + clientIP + " -p 23 -s 23 -V")
os.system("hping " + clientIP + " -s 23 -S -V")
os.system("hping " + clientIP + " -s 23 -V")

#Drop packets from outside with destination ports in the range of 32768 - 32775
os.system("hping " + clientIP + " -p 32768 -S -V")
os.system("hping " + clientIP + " -p 32768 -V")
os.system("hping " + clientIP + " -p 32775 -S -V")
os.system("hping " + clientIP + " -p 32775 -V")

#Drop TCP packets from outside with destination port 111
os.system("hping " + clientIP + " -p 111 -S -V")
os.system("hping " + clientIP + " -p 111 -V")

#Drop TCP packets from outside with destination port 515
os.system("hping " + clientIP + " -p 515 -S -V")
os.system("hping " + clientIP + " -p 515 -V")

#Can connect to interior PC using SSH from outside.
os.system("ssh " + clientIP)
