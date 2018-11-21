#!/usr/bin/python

#To remove the 'No Route Found for IPv6 Destination' error.
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR) 

from scapy.all import *
import sys

#Getting input from the user
def inputs():
	
	min_port = raw_input("[*] Min port number : ")
	#add is_valid_port
	
	max_port = raw_input("[*] Max port number : ")
	#add is_valid_port
	
	ip = raw_input("[*] Target ip address : ")
	#add is_valid_ip
	
	ports_range = range(int(min_port), int(max_port)+1)
	
	return {"ip":ip, "ports":ports_range}
	

#Testing if the target is up and running
def is_up(ip):
	
	#set level of verbosity to 0  /display nothing
	conf.verb = 0
	
	try:
		#the target is up if it sends back a response
		ping = sr1((IP((dst=ip)/ICMP))
		return True
	
	except Exception:
		#An Exception will raise if the target was down
		return False
