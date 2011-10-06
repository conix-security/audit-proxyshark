#!/usr/bin/python

import sys

from pyparsing import *

grammar = Forward()

direction = Optional(oneOf("src dst"))

ip = Combine(
	Word(nums, max=3) + Literal(".") + Word(nums, max=3) + Literal(".") +
	Word(nums, max=3) + Literal(".") + Word(nums, max=3)
)

hostname = Combine(Word(alphas) + Word(alphanums + "._"))

host = direction + Literal("host") + (ip | hostname)

net = direction + Literal("net") + Combine(ip + Literal("/") + Word(nums, max=2))

proto = oneOf("icmp tcp udp")

port = direction + Literal("port") + Word(nums, max=5)

op = oneOf("and or")

grammar << (
	Group(host | net | proto | port | nestedExpr(content=grammar)) +
	Optional(op + Group(grammar))
)

chains = []
def next_chain():
	global chains
	import random
	import time
	random.seed(time.time())
	chain = None
	while not chain or chain in chains:
		chain = random.randint(1000, 9999)
	chains.append(chain)
	return chain

def print_rules(pos, tokens):
	""" """
	# only on the entire string
	if pos > 0: return
	rules = make_rules(tokens)
	print "iptables -A OUTPUT -j PSHARK%s" % rules[0][0]
	for chain_start, string, chain_end in rules:
		print "iptables -A PSHARK%s %s -j PSHARK%s" % (chain_start, string, chain_end)
	print "iptables -A PSHARK%s -j NFQUEUE" % rules[-1][-1]
	#

def make_rules(tokens):
	""" """
	# if we have a token list
	if type(tokens[0]) == str:
		direction, param, value = [None] * (3 - len(tokens)) + list(tokens)
		# protocol
		if param is None:
			return [(next_chain(), "-p %s" % value, next_chain())]
		# address
		elif param in ["host", "net"]:
			rules = []
			chain_start = next_chain()
			chain_end = next_chain()
			if direction in [None, "src"]:
				rules.append((chain_start, "-s %s" % value, chain_end))
			if direction in [None, "dst"]:
				rules.append((chain_start, "-d %s" % value, chain_end))
			return rules
		# port
		elif param in ["port"]:
			rules = []
			chain_start = next_chain()
			chain_end = next_chain()
			if direction in [None, "src"]:
				rules.append((chain_start, "--sport %s" % value, chain_end))
			if direction in [None, "dst"]:
				rules.append((chain_start, "--dport %s" % value, chain_end))
			return rules
		# unknown parameter
		else:
			return []
	# if we have a single group
	elif len(tokens) == 1:
		return make_rules(tokens[0])
	# if we have a composition ('and' or 'or')
	elif len(tokens) == 3:
		if tokens[1] == "and":
			rules0 = make_rules(tokens[0])
			rules1 = make_rules(tokens[2])
			rules = []
			for chain_start, string, chain_end in rules1:
				if chain_start == rules1[0][0]: chain_start = rules0[-1][-1]
				if chain_end == rules1[0][0]: chain_end = rules0[-1][-1]
				rules.append((chain_start, string, chain_end))
			return rules0 + rules
		elif tokens[1] == "or":
			rules0 = make_rules(tokens[0])
			rules1 = make_rules(tokens[2])
			rules = []
			for chain_start, string, chain_end in rules1:
				if chain_start == rules1[0][0]: chain_start = rules0[0][0]
				elif chain_start == rules1[-1][-1]: chain_start = rules0[-1][-1]
				if chain_end == rules1[0][0]: chain_end = rules0[0][0]
				elif chain_end == rules1[-1][-1]: chain_end = rules0[-1][-1]
				rules.append((chain_start, string, chain_end))
			return rules0 + rules
		else:
			return []
	# unknown parameter
	else:
		return []

grammar.setParseAction(lambda string, pos, tokens: print_rules(pos, tokens))

string = "(tcp and dst host 1.2.3.4) or host 2.3.4.5 or (net 1.2.3.0/24 and (port 1234 and port 3333)) and udp and (icmp or src host 192.168.1.1) and dst port 8888 or host www.google.fr or port 123"
#string = "host 1.2.3.4 and (net 1.2.3.0/24 or port 13)"

grammar.parseString(string)









