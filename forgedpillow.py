#!/usr/bin/env python3

from scapy.all import *
import time

def fudgetime(year, month, day, pcapfilein, pcapfileout):
	packets = rdpcap(pcapfilein)

	#now = datetime.now()
	target = datetime(year, month, day, 0, 0, 0)
	
	ptime = datetime.fromtimestamp(int(packets[0].time))
	pday = datetime(ptime.year, ptime.month, ptime.day, 0, 0, 0)

	secondsdiff = (target - pday).total_seconds()

	for p in packets:
		p.time += secondsdiff

	wrpcap(pcapfileout, packets)

if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='Change date of files in a pcap.')
	parser.add_argument('year', metavar='YYYY', type=int, help='Year')
	parser.add_argument('month', metavar='MM', type=int, help='Month')
	parser.add_argument('day', metavar='DD', type=int, help='Day')
	parser.add_argument('pcapfilein', metavar='pcapfilein', type=argparse.FileType('r'), help='pcap file to modify')
	parser.add_argument('pcapfileout', metavar='pcapfileout', type=argparse.FileType('w'), help='output pcap file')

	args = parser.parse_args()

	fudgetime(args.year, args.month, args.day, args.pcapfilein.name, args.pcapfileout.name)
