import scapy
from scapy.all import *
from scapy.utils import PcapReader
path = "F:/Downloads/Attack.pcapng"
packets = rdpcap(path)

#TODO Finish the rest if not using CIC meter