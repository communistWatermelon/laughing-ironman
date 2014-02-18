'''
--------------------------------------------------------------------------------------------
--	SCRIPT:	    remoteFirewall.py
--
--	FUNCTIONS:  setupRouting
--                  firewallInit
--                  createUserChains
--                  dnsSetup
--                  enableTCPPortIn
--                  enableTCPPortOut
--                  enableUDPPortIn
--                  enableUDPPortOut
--                  enableICMPIn
--                  enableICMPOut
--
--	DATE:       February 13, 2014
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
USER DEFINED SECTION
"""
inputInt = "em1"
outputInt = "p3p1"

tcpPortsIn = ["22", "80", "443", "32770"]
tcpPortsOut = ["22", "80", "443", "32770"]
udpPortsIn = ["59"]
udpPortsOut = ["59"]
icmpTypesIn = ["0", "8"]
icmpTypesOut = ["0", "8"]

internalIP = "192.168.10.0/24"
externalIP = "192.168.0.13" 
IgatewayIP = "192.168.10.1"
OgatewayIP = "192.168.0.100"
"""
USER DEFINED SECTION
"""

def setupForwarding():
	print("Setup Forwarding")
	os.system("ifconfig " + outputInt + " " + IgatewayIP + " up")
	os.system("echo \"1\" >/proc/sys/net/ipv4/ip_forward")
	os.system("route add -net 192.168.0.0 netmask 255.255.255.0 gw " + OgatewayIP)
	os.system("route add -net " + internalIP + " gw " + IgatewayIP)

	os.system("iptables -t nat -A POSTROUTING -o " + inputInt + " -j MASQUERADE")
	#os.system("iptables -A FORWARD -i " + inputInt + " -o " + outputInt + " -m state --state  NEW,ESTABLISHED -j ACCEPT")
	#os.system("iptables -A FORWARD -i " + outputInt + " -o " + inputInt + " -m state --state  NEW,ESTABLISHED -j ACCEPT")
	
def createUserChains():
	print("Creating User Chains")
	os.system("iptables -N TCP")
	#os.system("iptables -N UserTCP")
	os.system("iptables -A TCP")
	#os.system("iptables -A UserTCP")
	
	os.system("iptables -N UDP")
	#os.system("iptables -N UserUDP")
	os.system("iptables -A UDP")	
	#os.system("iptables -A UserUDP")

	os.system("iptables -N ICMP")
	#os.system("iptables -N UserICMP")
	os.system("iptables -A ICMP")
	#os.system("iptables -A UserICMP")

def addUserChains():
	print("Linking User Chains")
	os.system("iptables -A FORWARD -p tcp -j TCP")
	#os.system("iptables -A TCP -p tcp -j UserTCP")
	
	os.system("iptables -A FORWARD -p udp -j UDP")
	#os.system("iptables -A UDP -p udp -j UserUDP")
	
	os.system("iptables -A FORWARD -p icmp -j ICMP")
	#os.system("iptables -A ICMP -p icmp -j UserICMP")

def firewallInit():
	print("Initializing Firewall")
	#Setting default Behavior
	os.system("iptables -P INPUT DROP")
	os.system("iptables -P OUTPUT DROP")
	os.system("iptables -P FORWARD DROP")

	#Dropping Suspicious IP Addresses
	os.system("iptables -A INPUT -s " + internalIP + " -i " + inputInt + " -j DROP")
	os.system("iptables -A FORWARD -s " + internalIP + " -i " + inputInt + " -j DROP")

	#Drops specifical edge-cases
	os.system("iptables -A TCP -p tcp --sport 0:1024 --dport 80 -j DROP")
	os.system("iptables -A TCP -p tcp --sport 0 -j DROP")

	os.system("iptables -A TCP -i " + externalIP  + " -p tcp --dport 32768:32775 -j DROP")
	os.system("iptables -A UDP -i " + externalIP  + " -p udp --dport 32768:32775 -j DROP")
	os.system("iptables -A TCP -i " + externalIP  + " -p tcp --dport 137:139 -j DROP")
	os.system("iptables -A UDP -i " + externalIP  + " -p tcp --dport 137:139 -j DROP")
	os.system("iptables -A TCP -i " + externalIP  + " -p tcp --dport 111 -j DROP")
	os.system("iptables -A TCP -i " + externalIP  + " -p tcp --dport 515 -j DROP")
	
	#Blocking all telnet packets
	os.system("iptables -A TCP -p tcp --sport 23 -j DROP")
	os.system("iptables -A TCP -p tcp --dport 23 -j DROP")

	#SSH Delay & FTP Throughput
	#os.system("iptables -A PREROUTING -t mangle -p tcp --sport 22 -j TOS --set-tos Minimize-Delay")
	#os.system("iptables -A PREROUTING -t mangle -p tcp --sport 21 -j TOS --set-tos Minimize-Delay")
	#os.system("iptables -A PREROUTING -t mangle -p tcp --sport 20 -j TOS --set-tos Maximize-Throughput")

def dnsSetup():
	print("DNS Setup")
	#os.system("iptables -A INPUT -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT")
	#os.system("iptables -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT")
	#os.system("iptables -A INPUT -p udp --dport 67:68 -j ACCEPT")

	os.system("iptables -A FORWARD -i " + inputInt  + " -o " + outputInt + " -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT")
	os.system("iptables -A FORWARD -i " + outputInt + " -o " + inputInt  + " -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A FORWARD -i " + inputInt  + " -o " + outputInt + " -p udp --dport 67:68 -j ACCEPT")

def enableTCPPortIn(port):
	print("In Forwarding TCP Port " + port)
	os.system("iptables -A TCP -i " + inputInt  + " -o " + outputInt + " -p tcp --sport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A TCP -i " + outputInt + " -o " + inputInt  + " -p tcp --dport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -t nat -A PREROUTING -i " + inputInt + " -p tcp --dport " + port + " -j DNAT --to 192.168.10.42")

def enableTCPPortOut(port):
	print("Out Forwarding TCP Port " + port)
	os.system("iptables -A TCP -i " + outputInt + " -o " + inputInt  + " -p tcp --sport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A TCP -i " + inputInt  + " -o " + outputInt + " -p tcp --dport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT")

def enableUDPPortIn(port):
	print("In Forwarding UDP Port " + port)	
	os.system("iptables -A UDP -o " + outputInt + " -i " + inputInt + " -p udp --sport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A UDP -o " + inputInt + "  -i " + outputInt + " -p udp --dport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -t nat -A PREROUTING -i " + inputInt + " -p udp --dport " + port + " -j DNAT --to 192.168.10.42")

def enableUDPPortOut(port):
	print("Out Forwarding UDP Port " + port)
	os.system("iptables -A UDP -o " + outputInt + " -i " + inputInt + " -p udp --dport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A UDP -o " + inputInt + "  -i " + outputInt + " -p udp --sport " + port + " -m state --state NEW,ESTABLISHED -j ACCEPT")
	
def enableICMPIn(itype):
	print("In Forwarding ICMP type " + itype)
	os.system("iptables -A ICMP -i " + inputInt + " -o " + outputInt + " -p icmp --icmp-type " + itype + " -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A ICMP -i " + outputInt + "  -o " + inputInt + " -p icmp --icmp-type " + itype + " -m state --state NEW,ESTABLISHED -j ACCEPT")
#	os.system("iptables -t nat -A PREROUTING -i " + inputInt + " -p icmp " + itype + " -j DNAT --to 192.168.10.42")

def enableICMPOut(itype):
	print("Out Forwarding ICMP type " + itype)
	os.system("iptables -A ICMP -i " + outputInt + " -o " + inputInt + " -p icmp --icmp-type " + itype + " -m state --state NEW,ESTABLISHED -j ACCEPT")
	os.system("iptables -A ICMP -i " + inputInt + "  -o " + outputInt + " -p icmp --icmp-type " + itype + " -m state --state NEW,ESTABLISHED -j ACCEPT")

def main():
	while True:
		os.system("clear")
		print("R - run script")
		print("\n==TCP Ports In==")
		for i in tcpPortsIn:
			print(i + " ")
		print("\n==TCP Ports Out==")
		for i in tcpPortsOut:
			print(i + " ")
		print("\n==UDP Ports In==")
		for i in udpPortsIn:
			print(i + " ")
		print("\n==UDP Ports Out==")
		for i in udpPortsOut:
			print(i + " ")
		print("\n==ICMP Types In==")
		for i in icmpTypesIn:
			print(i + " ")
		print("\n==ICMP Types Out==")
		for i in icmpTypesOut:
			print(i + " ")
		print("\nSelect a command: ")

		choice = raw_input()
		
		if choice == 'R' or choice == 'r':
			#Clearing old firewall rules
			os.system("iptables -F")
			os.system("iptables -X")
			os.system("iptables -t nat -F")

			createUserChains()
			setupForwarding()
			firewallInit()
			addUserChains()
			
			for i in tcpPortsIn:
				enableTCPPortIn(i)			
			for i in tcpPortsOut:
				enableTCPPortOut(i)
			for i in udpPortsIn:
				enableUDPPortIn(i)			
			for i in udpPortsOut:
				enableUDPPortOut(i)
			for i in icmpTypesIn:
				enableICMPIn(i)
			for i in icmpTypesOut:
				enableICMPOut(i)

			#os.system("iptables -A INPUT -p tcp --syn -j DROP")
			os.system("iptables -A FORWARD -o " + inputInt  + " -i " + outputInt + " -p tcp --syn -j DROP")

			dnsSetup()
			print("Setup Complete\n")
			break
		else:
			print("Invalid input\n")

main()

