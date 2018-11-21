#!/usr/bin/python

#To remove the 'No Route Found for IPv6 Destination' error.
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR) 

from scapy.all import *
import sys


