#!/usr/bin/python

#To remove the 'No Route Found for IPv6 Destination' error.
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR) 

from scapy.all import * 
import sys 	#for system calls
import re 	#for regular expression 

#Getting input from the user
def inputs():
	
	min_port = int(raw_input("[*] Min port number : "))
	#Testin if is_valid_port
	if is_valid_port(min_port) is not True:
		print "[!] Unvalid port number."
		#Exit the program with exit code = 1 / there was an error
		sys.exit(1)
	
	max_port = int(raw_input("[*] Max port number : "))
	#Testing is_valid_port
	if is_valid_port(min_port) is not True or min_port > max_port:
		print "[!] Unvalid port number."
		#Exit the program with exit code = 1 / there was an error
		sys.exit(1)
	
	ip = str(raw_input("[*] Target ip address : "))
	#Testing if is_valid_ip
	if is_valid_ip(ip) is not True:
		print "[!] Unvalid ip address."
		#Exit the program with exit code = 1 / there was an error
		sys.exit(1)
	
	ports_range = range(int(min_port), int(max_port)+1)
	
	return {"ip":ip, "ports":ports_range}
	

#Testing if the target is up and running
def is_up(ip):
	
	#set level of verbosity to 0  /display nothing
	conf.verb = 0
	
	try:
		#the target is up if it sends back a response
		ping = sr1(IP(dst=ip)/ICMP)
		return True
	
	except Exception:
		#An Exception will raise if the target was down
		return False

#Testing if the port is valid
def is_valid_port(port):
	
	if isinstance(port,int) and port >= 0 and port <= 255 :
		return True
	else:
		return False
		
#Testing if the ip is valid
def is_valid_ip(ip):
	if re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", ip) is None:
 		return False
	else:
	 	return True

#Scanning port
def scan_port(p, ip):
	#rundom source port
	sp = RandShort()
	
	conf.verb = 0
	#send and receive a packet from the target
	pkt = sr1(IP(dst=ip)/TCP(sport = sp, dport = p, flags = "S"))
	
	#retreive the flags from the recieved packet
	f = pkt.getlayer(TCP).flags
	
	#See if the port is open
	if f == 0x12 : 
		return True
	else:
		return False
	
	#send the reset packet
	send(IP(dst=ip)/TCP(sport = sp, dport = p, flags = "R"))
		
if __name__ == "__main__":
	
	try:
	
		the_inputs = inputs()
		ip = the_inputs.get("ip")
		ports = the_inputs.get("ports")
	
		print "[+] Scanning started ..."
		for port in ports :
			if scan_port(port, ip) is True :
				print "[+] Port " + post + " is open."
			else:
				print "[-] Port " + post + " is closed."
	
		print "[+] Scanning finished."
	
	except KeyboardInterrupt:
	
		print "[x] Exit."
		sys.exit(0)
	
	except Exception:
	
		print "[x] There was an error."
		sys.exit(1)
	
	
	
	
	
	
	
	
	
	
	
	
	
