#!/usr/bin/python

from scapy.all import *

def rdpcap_and_close(filename, count=-1):
    pcap_reader = PcapReader(filename)
    packets = pcap_reader.read_all(count=count)
    pcap_reader.close()
    return packets
