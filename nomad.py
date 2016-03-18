#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import argparse
import sys
import json
import logging
import binascii
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from utils import *

JOBID 					= "jobid"
TASKID 					= "taskid"
ALLOCID 				= "allocid"
PUTTS					= "putts"
CREATETS				= "createts"
ACKCREATETS 			= "ackcreatets"
IDCREATETS				= "idcreatets"
IDREPLYTS				= "idreplyts"
TERMTS					= "termts"
ACKTERMTS				= "acktermts"
allocid_jobs 			= {}
ack_jobs				= {}
name_jobs				= {}
allocid_ts				= {}

ACK 			 		= 0x010
PSH_ACK 		 		= 0x018
HTTP_OK_MESSAGE  		= "200 OK"
HTTP_PUT_MESSAGE 		= "PUT /v1/jobs"

NOMAD_SERVER_HTTP_PORT 	= 4646
NOMAD_SERVER_RPC_PORT  	= 4647

def evaluateNomadServer(file_name):

	print "Evaluating Nomad Server"

	global ack_jobs

	packets = rdpcap_and_close(file_name)
	for packet in packets:
		if TCP in packet:

			dport   = packet[TCP.name].dport
			payload = packet[TCP.name].payload.__str__()
			sport   = packet[TCP.name].sport
			flags   = packet[TCP.name].flags
			ack 	= str(packet[TCP.name].ack)
			seq		= str(packet[TCP.name].seq)

			if HTTP_PUT_MESSAGE in payload and dport == NOMAD_SERVER_HTTP_PORT:
				found = re.search('"ID":"(.+?)"', payload)
				if found:
					name 						= found.group(1)
					ts 							= packet.time
					name_jobs[name][PUTTS] 		= ts
				else:
					print "regex not working properly"
					sys.exit(-1)

			elif (flags == PSH_ACK or flags == ACK) and sport == NOMAD_SERVER_RPC_PORT:
				found_names 	= re.findall('([a-zA-Z0-9\-\_]{8,10}).Parent', payload)
				found_allocids	= re.findall('([a-zA-Z0-9\-\_]{36}).Job', payload)

				if len(found_names) != len(found_allocids):
					print "trace not usable"
					sys.exit(-1)

				allocids = []

				for name, allocid in zip(found_names, found_allocids):
					ts 									= packet.time
					ts_put								= name_jobs[name][PUTTS]
					allocid_jobs[allocid][CREATETS] 	= ts
					allocid_jobs[allocid][PUTTS]		= ts_put
					allocids.append(allocid_jobs[allocid][ALLOCID])
				
				if len(found_names) > 0 and len(found_allocids) > 0:
					ack_jobs[ack] = allocids

			elif flags == ACK and dport == NOMAD_SERVER_RPC_PORT and ack_jobs.get(seq):
				allocids 	= ack_jobs[seq]
				ts 			= packet.time
				for allocid in allocids:
					allocid_jobs[allocid][ACKCREATETS] 	= ts

	for k,v in allocid_jobs.items():
		createts 	= v.get(CREATETS)
		putts 		= v.get(PUTTS)
		ackcreatets = v.get(ACKCREATETS)

		if createts and putts and ackcreatets:
			print "###################################################"
			print "key:", k
			
			scheduling = (createts - putts)
			if scheduling > 1:
				print "scheduling:", scheduling, "[s]"
			else:
				print "scheduling:", scheduling*1000, "[ms]"

			ack = (ackcreatets - createts)
			if ack > 1:
				print "ack creation:", ack, "[s]"
			else:
				print "ack creation:", ack*1000 , "[ms]"

	print

	#print json.dumps(allocid_jobs, sort_keys=True, indent=4)

def evaluateNomadClient(file_name):
	
	print "Evaluating Nomad Client"

	global allocid_ts

	packets = rdpcap_and_close(file_name)

	i = 1

	for packet in packets:
		if TCP in packet:

			payload 	= packet[TCP.name].payload.__str__()
			sport   	= packet[TCP.name].sport
			dport   	= packet[TCP.name].dport
			flags   	= packet[TCP.name].flags
			ack 		= str(packet[TCP.name].ack)
			seq			= str(packet[TCP.name].seq)

			if flags == PSH_ACK and sport == NOMAD_SERVER_RPC_PORT:
				matches 	= re.findall('([a-zA-Z0-9\-\_]{36})', payload)
				for match in matches:
					allocid_ts[match] 				= {}
					allocid_ts[match][IDCREATETS] 	= packet.time

			elif flags == PSH_ACK and dport == NOMAD_SERVER_RPC_PORT:
				matches 		= re.findall('([a-zA-Z0-9\-\_]{36})', payload)
				node_ids 		= re.findall('NodeID.+([a-zA-Z0-9\-\_]{36})', payload)
				found_desired	= re.search('DesiredStatus', payload)
				node_register	= re.search('Node.Register', payload)

				if node_register:
					continue

				if not found_desired:
					ts_id_reply = packet.time
					for match in matches:
						if match not in node_ids:
							ts_id_create 					= allocid_ts[match][IDCREATETS]
							allocid_jobs[match][IDREPLYTS]	= ts_id_reply
							allocid_jobs[match][IDCREATETS]	= ts_id_create
				else:
					ts_term 	= packet.time
					allocids 	= []
					for match in matches:
						if match not in node_ids:
							allocid_jobs[match][TERMTS]	= ts_term
							allocids.append(match)

					if len(matches) > 0 and len(matches) > len(node_ids):
						ack_jobs[ack] = allocids

			elif flags == ACK and sport == NOMAD_SERVER_RPC_PORT and ack_jobs.get(seq):
				allocids 	= ack_jobs[seq]
				ts 			= packet.time
				for allocid in allocids:
					allocid_jobs[allocid][ACKTERMTS] = ts
		i = i + 1

	for k,v in allocid_jobs.items():
		idcreatets 	= v.get(IDCREATETS)
		idreplyts 	= v.get(IDREPLYTS)
		termts 		= v.get(TERMTS)
		acktermts 	= v.get(ACKTERMTS)

		if idcreatets and idreplyts and termts and acktermts:
			print "###################################################"
			print "key:", k
			
			termination = (termts - idcreatets)
			if termination > 1:
				print "termination:", termination, "[s]"
			else:
				print "termination:", termination*1000, "[ms]"

			acktermination = (acktermts - termts)
			if acktermination > 1:
				print "ack termination:", acktermination, "[s]"
			else:
				print "ack termination:", acktermination*1000 , "[ms]"
	
	print

	#print json.dumps(allocid_jobs, sort_keys=True, indent=4)

def define_connections(file_name):

	global allocid_jobs
	global name_jobs

	packets = rdpcap_and_close(file_name)
	for packet in packets:
		if TCP in packet:

			dport   = packet[TCP.name].dport
			payload = packet[TCP.name].payload.__str__()
			sport   = packet[TCP.name].sport

			if HTTP_PUT_MESSAGE in payload and dport == NOMAD_SERVER_HTTP_PORT:
				found = re.search('"ID":"(.+?)"', payload)
				if found:
					name 				= found.group(1)
					job 				= {}
					job[JOBID]			= name
					name_jobs[name]		= job
				else:
					print "regex not working properly"
					sys.exit(-1)

	for packet in packets:
		if TCP in packet:

			flags   = packet[TCP.name].flags
			sport   = packet[TCP.name].sport
			dport   = packet[TCP.name].dport
			payload = packet[TCP.name].payload.__str__()

			if (flags == PSH_ACK or flags == ACK)  and sport == NOMAD_SERVER_RPC_PORT:
				
				found_names 	= re.findall('([a-zA-Z0-9\-\_]{8,10}).Parent', payload)
				found_allocids	= re.findall('([a-zA-Z0-9\-\_]{36}).Job', payload)

				if len(found_names) != len(found_allocids):
					print "trace not usable"
					sys.exit(-1)

				for name, allocid in zip(found_names, found_allocids):

					job 					= {}
					job[ALLOCID] 			= allocid
					job[JOBID]				= name
					allocid_jobs[allocid] 	= job

	#print json.dumps(allocid_jobs, sort_keys=True, indent=4)

def evaluate(input):

	define_connections(input.file)

	if   input.action == "client":
		evaluateNomadClient(input.file)
	elif input.action == "server":
		evaluateNomadServer(input.file)
	elif input.action == "all":
		evaluateNomadServer(input.file)
		evaluateNomadClient(input.file)

def parse_cmd_line():
	parser = argparse.ArgumentParser(description='Nomad measurement tools')
	parser.add_argument('--client', dest='action', action='store_const', const='client', default='', help='Evaluate Client timings')
	parser.add_argument('--server', dest='action', action='store_const', const='server', default='', help='Evaluate Server timings')
	parser.add_argument(   '--all', dest='action', action='store_const',    const='all', default='', help='Evaluate Client and Server timings')
	parser.add_argument(  '--file',   dest='file',       action='store',     			 default='', help='File with the packets captures, e.g. capt.pcap')
	args = parser.parse_args()    
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)    
	return args			

if __name__ == '__main__':
	input = parse_cmd_line()
	evaluate(input)
	
