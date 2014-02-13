'''
--------------------------------------------------------------------------------------------
--	SCRIPT:	    remoteFirewall.py
--
--	FUNCTIONS:  setupRouting
--                  firewallInit
--                  createUserChains
--                  dnsSetup
--                  enableTCPPort
--                  enableUDPPort
--                  enableICMP
--
--	DATE:       February 3, 2014
--
--	REVISIONS:  (Date and Description)
--
--	DESIGNERS:  John Payment
--                  Jake Miner
--
--	PROGRAMMER: John Payment
--                  Jake Miner
--
--	NOTES: This program will setup a linux firewall using iptables. By default it blocks
--             everything that is not a dns lookup and requires the user to specify allowed
--             ports.
---------------------------------------------------------------------------------------------
'''
import os

"""
User Defined Section
"""
inputInt="em1"
outputInt="p3p1"
tcpPorts = []
ackPorts = []
udpPorts = []
icmpTypes = []
internalIP = "192.168.10.0/24"
externalIP = "192.168.0.11" 
IgatewayIP = "192.168.10.1"
OgatewayIP = "192.168.0.100"


def setupForwarding():
	os.system("ifconfig " + outputInt + " " + igatewayIP + " up")
	os.system("echo \"1\" >/proc/sys/net/ipv4/ip_forward")
	os.system("route add -net 192.168.0.0 netmask 255.255.255.0 gw")
	os.system("route add -net " + internalIP + " gw " + IgatewayIP)

	os.system("iptables -t nat -A POSTROUTING -o " + inputInt + " -j MASQUERADE")
	os.system("iptables -A FORWARD -i " + inputInt + " -o " + outputInt + " -m state --state  NEW,ESTABLISHED,RELATED -j ACCEPT")
	os.system("iptables -A FORWARD -i " + outputInt + " -o " + inputInt + " -m state --state  NEW,ESTABLISHED,RELATED -j ACCEPT")

def firewallInit():
	#Clearing old firewall rules
	os.system("iptables -F")

	#Setting default Behavior
	os.system("iptables -P INPUT DROP")
	os.system("iptables -P OUTPUT DROP")
	os.system("iptables -P FORWARD DROP")

	#Drops specifical edge-cases
	os.system("iptables -A INPUT -p tcp --sport 0:1024 --dport 80 -j DROP")
	os.system("iptables -A INPUT -p tcp --sport 0 -j DROP")
	os.system("iptables -A OUTPUT -p tcp --sport 0 -j DROP")

	os.system("iptables -p tcp --dport 32768:32775 -j DROP")
	os.system("iptables -p udp --dport 32768:32775 -j DROP")
	os.system("iptables -p tcp --dport 111 -j DROP")
	os.system("iptables -p tcp --dport 515 -j DROP")
	
	#Blocking syn+ack packets
	os.system("iptables -A INPUT -p tcp --syn --fin -j DROP")
	#Blocking all telnet packets
	os.system("iptables -p tcp --sport 23 -j DROP")
	os.system("iptables -p tcp --dport 23 -j DROP")
	
def createUserChains():
	os.system("iptables -N TCP")
	os.system("iptables -p tcp -j TCP")
	
	os.system("iptables -N UDP")
	os.system("iptables -p udp -j UDP")
	
	os.system("iptables -N ICMP")
	os.system("iptables -p icmp -j ICMP")

def dnsSetup():
	os.system("iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT")
	os.system("iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A INPUT -p udp --dport 67:68 -j ACCEPT")

def enableTCPPort(port):
	arg1 = "iptables -A INPUT -p tcp --sport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT"
	arg2 = "iptables -A INPUT -p tcp --dport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT"
	arg3 = "iptables -A OUTPUT -p tcp --sport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT"
	arg4 = "iptables -A OUTPUT -p tcp --dport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT"
	os.system(arg1)
	os.system(arg2)
	os.system(arg3)
	os.system(arg4)

def enableUDPPort(port):
	arg1 = "iptables -A INPUT -p udp --sport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT"
	arg2 = "iptables -A INPUT -p udp --dport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT"
	arg3 = "iptables -A OUTPUT -p udp --sport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT"
	arg4 = "iptables -A OUTPUT -p udp --dport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT"
	os.system(arg1)
	os.system(arg2)
	os.system(arg3)
	os.system(arg4)
	
def enableICMP(type):
	arg1 = "iptables -A INPUT -p icmp --icmp-type " + type + " -m state --state NEW,ESTABLISHED -j ACCEPT"
	arg2 = "iptables -A OUTPUT -p icmp --icmp-type " + type + " -m state --state NEW,ESTABLISHED -j ACCEPT"
	os.system(arg1)
	os.system(arg2)

def main():
	while True:
		os.system("clear")
		print("T - add a TCP port to be forwarded")
		print("A - add a TCP port to be forwarded and allow ACKs")
		print("U - Add a UDP port to be forwarded")
		print("I - Add an ICMP type yo be forwarded")
		print("R - run script")
		print("\n==TCP Ports==")
		for i in tcpPorts:
			print(i + " ")
		print("\n==TCP-ACK Ports==")
		for i in ackPorts:
			print(i + " ")
		print("\n==UDP Ports==")
		for i in udpPorts:
			print(i + " ")
		print("\n==ICMP Types==")
		for i in icmpTypes:
			print(i + " ")
		print("\nSelect a command: ")

		choice = raw_input()
		
		if choice == 'T' or choice == "t":
			print("Input port to be forwarded: ")
			tcpPorts.append(raw_input())
		elif choice == 'A' or choice == "a":
			print("Input port to be forwarded: ")
			ackPorts.append(raw_input())
		elif choice == 'U' or choice == "u":
			print("Input port to be forwarded: ")
			udpPorts.append(raw_input())
		elif choice == 'I' or choice == "i":
			print("Input ICMP type to be forwarded: ")
			icmpTypes.append(raw_input())
		elif choice == 'R' or choice == "r":
			#setupForwarding("192.168.10.1", "192.168.0.100")
			firewallInit()
			createUserChains()
			
			for i in ackPorts:
				enableTCPPort(i)
			
			os.system("iptables -A INPUT -p tcp --syn -j DROP")
			
			for i in udpPorts:
				enableUDPPort(i)
			for i in tcpPorts:
				enableTCPPort(i)
			for i in icmpTypes:
				enableICMP(i)

			dnsSetup()
			print("Setup Complete\n")
			break
		else:
			print("Invalid input\n")

main()

