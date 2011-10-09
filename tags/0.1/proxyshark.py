#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# This file is part of proxyshark, a tool designed to dissect and alter IP
# packets on-the-fly.
#
# Copyright (c) 2011 by Nicolas Grandjean <ncgrandjean@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# ignore signals for now in order to let all the stuff load properly without
# user interrupt, we will re-enable signal handling later to intercept Ctrl-C
# and things like that
import signal
handler_sigint = signal.getsignal(signal.SIGINT)
signal.signal(signal.SIGINT, signal.SIG_IGN)

# imports

import cProfile
import getopt
import libnetfilter_queue as libnfq
import logging
import lxml.etree as etree
import os
import re
import socket
import string
import time

from StringIO import *
from subprocess import *
from threading import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def one_line(obj):
	""" Return the 1-line string representation of an object. """
	return str(obj).replace("\n", " ")

###############################################################################
# Classes (dissector)
###############################################################################

class DissectedField:
	"""
	A field from any protocol supported by libwireshark. All the attributes are
	read-only.

	  etree_field  -- etree.Element containing the PDML <field/> tag
	  pos          -- offset from the beginning of the packet
	  size         -- size of the field in bytes
	  bytes        -- raw data (example for a 2-bytes field: "\\x03\\x01")
	  pretty_bytes -- printable representation of the raw data
	  hexa         -- ASCII representation of the bytes ("0301")
	  pretty_hexa  -- the same with pipes and blank-separated bytes
	                  ("|03 01|"), can also be a mix such as "abc|0d 0a|"
	  pretty_value -- a human-readable interpretation ("TLS 1.0")
	  name         -- the field name without the protocol ("record.version")
	  pretty_name  -- a well-formatted name ("Version")
	"""
	def __init__(self, etree_field):
		"""
		Creates a new DissectedField instance.

		  etree_field -- an etree.Element instance from a PDML <field/> tag
		"""
		self.etree_field = etree_field
		# skip the field if the "hide" attribute is set
		attr_hide = etree_field.get("hide")
		if attr_hide == "yes":
			raise ValueError("hidden fields are not supported")
		# the field must have a valid "pos" attribute
		attr_pos = etree_field.get("pos")
		if not attr_pos or not attr_pos.isdigit():
			raise ValueError(one_line(
				"invalid \"pos\" attribute %s" % repr(attr_pos)))
		self.pos = int(attr_pos)
		# the field must have a valid "size" attribute
		attr_size = etree_field.get("size")
		if not attr_size or not attr_size.isdigit() or attr_size == "0":
			raise ValueError(one_line(
				"invalid \"size\" attribute %s" % repr(attr_size)))
		self.size = int(attr_size)
		# the field must have a "value" attribute with hexa data
		attr_unmaskedvalue = etree_field.get("unmaskedvalue")
		if attr_unmaskedvalue:
			attr_value = attr_unmaskedvalue
		else:
			attr_value = etree_field.get("value")
			if not attr_value:
				raise ValueError("the \"value\" attribute was not found")
		if len(attr_value) != self.size * 2:
			raise ValueError("incoherent field size")
		self.bytes = self.__hexa_to_bytes(attr_value)
		self.pretty_bytes = repr(self.bytes)
		self.hexa = attr_value
		# the field name and the printable value can be found in 2 ways:
		#   - we have valid "name" and "showname" attributes so we get both
		#     from them
		#   - we don't have "name" attribute but we have a ":"-separated "show"
		#     attribute which contains the name and the value we need
		attr_name = etree_field.get("name")
		attr_show = etree_field.get("show")
		attr_showname = etree_field.get("showname")
		if attr_name and ": " in attr_showname:
			# we don't want the protocol name so "ip.dst" becomes "dst"
			name = attr_name.rpartition(".")[2]
			pretty_name, _, pretty_value = attr_showname.partition(": ")
		elif ": " in attr_show:
			name = ""
			pretty_name, _, pretty_value = attr_show.partition(": ")
			for char in pretty_name.lower():
				if not char.isalnum(): char = "_"
				name += char
		else:
			# can't find a valid name for this field
			name = "data"
			pretty_name = "Data"
			pretty_value = self.__bytes_to_pretty_hexa(self.bytes)
		self.name = name
		self.pretty_name = pretty_name
		if pretty_value.startswith("("):
			self.pretty_value = pretty_value
		else:
			self.pretty_value = pretty_value.partition("(")[0].strip()
		#
	def __len__(self):
		""" Returns the number of bytes in the field. """
		return self.size
		#
	def __repr__(self):
		"""
		Returns the field attributes printed as a dictionary.

		Example: "{'pos': 2, 'size': 2, 'bytes': '\\x02X', 'hexa': '0258',
		'pretty_hexa': '|02 58|', 'pretty_value': '600', 'name': 'len',
		'pretty_name': 'Total Length'}"
		"""
		def __repr__(attr_name):
			return "'%s': %s" % (attr_name, repr(getattr(self, attr_name)))
		result = "{"
		result += ", ".join([__repr__(attr_name) for attr_name in [
				"pos", "size", "bytes", "hexa",
				"pretty_hexa", "pretty_value", "name", "pretty_name"
		]])
		result += "}"
		return result
		#
	def __str__(self):
		"""
		Returns the field as a well-formatted string.

		Example: "Total Length: '600' ('|02 58|')"
		"""
		result = "%s: %s" % (self.pretty_name, repr(self.pretty_value))
		if self.pretty_value != self.pretty_hexa:
			result += " (%s)" % repr(self.pretty_hexa)
		return result
		#
	def __bytes_to_pretty_hexa(self, bytes, fullhexa=False):
		""" Example: "\\x61\\x62\\x63\\x0d\\x0a" -> "abc|0d 0a|" """
		pretty_hexa = ""
		hexa_block = [] 
		printable_chars = list(
			string.digits + string.letters + string.punctuation + " "
		)
		printable_chars.remove("|")
		for byte in bytes:
			if byte in printable_chars and not fullhexa:
				if hexa_block:
					pretty_hexa += "|%s|" % " ".join(hexa_block)
					hexa_block = []
				pretty_hexa += byte
			else:
				hexa_block.append(
					hex(ord(byte)).partition("0x")[2].rjust(2, "0")
				)
		if hexa_block:
			pretty_hexa += "|%s|" % " ".join(hexa_block)
		return pretty_hexa
		#
	def __get_pretty_hexa(self):
		"""
		Returns a pretty ASCII representation of the field. Non-printable
		characters are printed in hexa between pipes and blank-separated.

		Example: "Content-Length: 104|0d 0a|"
		"""
		match = re.match(
			"^(.*:\s+)?(0x)?([0-9a-f]+)(\s+.*)?$",
			self.pretty_value.lower()
		)
		fullhexa = match and not ": " in self.bytes
		return self.__bytes_to_pretty_hexa(self.bytes, fullhexa)
		#
	def __hexa_to_bytes(self, hexa):
		""" Example: "6162630d0a" -> "\\x61\\x62\\x63\\x0d\\x0a" """
		bytes = ""
		while hexa:
			bytes += chr(int(hexa[:2], 16))
			hexa = hexa[2:]
		return bytes
		#
	def __norm_pretty_hexa(self, pretty_hexa):
		""" Example: "abc| 0d  0A |" -> "abc|0d 0a|" """
		result = ""
		for i, block in __builtins__.enumerate(pretty_hexa.split("|")):
			# even blocks are printable and odd blocks are hexa blocks
			if i % 2 == 0:
				result += block
			else:
				match = re.match(
					"^\s*([0-9a-f]{2}(\s+[0-9a-f]{2})*)\s*$",
					block.lower()
				)
				if match:
					result += "|%s|" % re.sub("\s{2,}", " ", match.group(1))
				else:
					raise ValueError(one_line(
						"invalid pretty hexa value %s" % repr(pretty_hexa)))
		return result
		#
	def __pretty_hexa_to_bytes(self, pretty_hexa):
		""" Example: "abc|0d 0a|" -> "\\x61\\x62\\x63\\x0d\\x0a" """
		bytes = ""
		pretty_hexa = self.__norm_pretty_hexa(pretty_hexa)
		for i, block in __builtins__.enumerate(pretty_hexa.split("|")):
			# even blocks are printable and odd blocks are hexa blocks
			if i % 2 == 0:
				bytes += block
			else:
				block = block.replace(" ", "")
				while block:
					bytes += chr(int(block[:2], 16))
					block = block[2:]
		return bytes
		#
	pretty_hexa = property(fget=__get_pretty_hexa)
	#

class DissectedProto(list):
	"""
	A protocol as seen in Wireshark (geninfo, frame, ip, tcp, http, ... ).

	  etree_proto -- etree.Element containing the PDML <proto/> tag
	  name        -- protocol name
	  pretty_name -- a printable description
	"""
	def __init__(self, etree_proto):
		"""	
		Creates a new DissectedProto instance:
		  etree_proto -- an etree.Element instance from a PDML <proto/> tag
		"""
		self.etree_proto = etree_proto
		# get the protocol name
		attr_name = etree_proto.get("name")
		if not attr_name:
			raise ValueError("unable to find the protocol name")
		self.name = attr_name
		# get the protocol description
		attr_showname = etree_proto.get("showname")
		if not attr_showname:
			attr_showname = attr_name
		self.pretty_name = attr_showname
		# decode the fields
		for etree_field in self.etree_proto:
			self.__decode_field(etree_field)
		#
	def __str__(self):
		""" Returns the protocol as a well-formatted string. """
		result = "    %s:\n" % self.pretty_name
		for dissected_field in self:
			result += "        %s\n" % str(dissected_field)
		return result
		#
	def __decode_field(self, etree_field):
		""" Decode a field recursively. """
		try:
			self.append(DissectedField(etree_field))
		except ValueError, exception:
			logging.debug(exception)
		finally:
			for etree_subfield in etree_field:
				self.__decode_field(etree_subfield)
		#
	#

class DissectedPacket(list):
	"""
	A packet as seen by Wireshark (a tree of protocols and fields).

	  description  -- general description from the TShark output in text mode
	  etree_packet -- etree.Element containing the PDML <packet/> tag
	  identifier   -- a integer which is guaranteed to be unique and constant
	                  for this packet
	  timestamp    -- arrival time taken from the description
	  source       -- source IP address
	  destination  -- destination IP address
	  protocol     -- last protocol layer
	  info         -- short packet summary
	"""
	nb_dissected_packets = 0
	#
	def __init__(self, description, etree_packet):
		"""
		Creates a new DissectedPacket instance.

		  description  -- packet descrition from TShark in text mode
		  etree_packet -- an etree.Element instance from a PDML <packet/> tag
		"""
		description = re.sub("  +", " ", description)
		self.description = description
		self.etree_packet = etree_packet
		# calculate the packet identifier
		DissectedPacket.nb_dissected_packets += 1
		self.identifier = DissectedPacket.nb_dissected_packets
		# get the packet attributes from the description
		findall = re.findall(
			"^(\d+.\d+) ([^ ]+) -> ([^ ]+) ([^ ]+) (.*)$",
			description
		)
		if findall:
			self.timestamp = float(findall[0][0])
			self.source = findall[0][1]
			self.destination = findall[0][2]
			self.protocol = findall[0][3]
			self.info = findall[0][4]
		else:
			raise ValueError("invalid description %s" % description)
		# decode the protocols
		for etree_proto in etree_packet:
			dissected_proto = DissectedProto(etree_proto)
			if dissected_proto:
				self.append(dissected_proto)
		#
	def __str__(self):
		""" Returns the packet as a well-formatted string. """
		result = "Packet #%s, %s:\n\n" % (self.identifier, self.description)
		result += "    Timestamp: %s\n" % repr(self.timestamp)
		result += "    Source: %s\n" % repr(self.source)
		result += "    Destination: %s\n" % repr(self.destination)
		result += "    Protocol: %s\n" % repr(self.protocol)
		result += "    Info: %s\n" % repr(self.info)
		result += "\n"
		for proto in self:
			result += "%s\n" % str(proto)
		return result
		#
	#

class Dissector:
	""" A packet dissector based on TShark. """
	def __init__(self):
		"""
		Creates a new Dissector instance by running two instances of TShark;
		one in text mode (-T text) to get general packet descriptions and the
		other one in PDML mode (-T pdml) to get complete packet dissection
		with protocols and fields.
		"""
		self.__stopping = Event()
		# use tshark from the command line argument
		global arg_tshark_binary
		tshark_path = os.path.join(os.getcwd(), arg_tshark_binary)
		# global pcap header for tshark initialization
		pcap_global_header = (
			"\xd4\xc3\xb2\xa1" # magic number
			"\x02\x00"         # major version
			"\x04\x00"         # minor version
			"\x00\x00\x00\x00" # GMT to local correction
			"\x00\x00\x00\x00" # accuracy of timestamps
			"\xff\xff\x00\x00" # snaplen
			"\x65\x00\x00\x00" # data link type
		)
		# run tshark instances
		self.__tshark = {}
		for mode in ["text", "pdml"]:
			cmdline = "%s -i - -s0 -n -l -T %s" % (tshark_path, mode)
			self.__tshark[mode] = Popen(
				(cmdline).split(" "), stdin=PIPE, stdout=PIPE, stderr=PIPE)
			self.__tshark[mode].stdin.write(pcap_global_header)
			self.__tshark[mode].stdin.flush()
			time.sleep(0.5)
			self.__tshark[mode].poll()
			if self.__tshark[mode].returncode >= 0:
				raise RuntimeError("running tshark in %s mode failed" % mode)
			self.__tshark[mode].stderr.close()
		logging.info("dissector started")
		#
	def __ensure_is_running(self, restart_attempts=None):
		""" Ensures that TShark is running. """
		max_restart_attempts = 3
		if restart_attempts is None:
			restart_attempts = max_restart_attempts
		# check if tshark is running
		for mode in ["text", "pdml"]:
			self.__tshark[mode].poll()
			if self.__tshark[mode].returncode >= 0: break
		# still running
		else:
			return
		# not running, try to restart it
		if not self.__stopping.isSet():
			self.__stop()
			if restart_attempts:
				logging.info("restarting dissector...")
				time.sleep((1 + max_restart_attempts - restart_attempts)**2)
				self.__init__()
				self.__ensure_is_running(restart_attempts - 1)
			else:
				raise RuntimeError(
					"tshark is not running and cannot be restarted"
				)
		#
	def __stop(self):
		""" Stops TShark instances properly. """
		for mode in ["text", "pdml"]:
			tshark = self.__tshark[mode]
			for send_signal in [tshark.terminate, tshark.kill]:
				tshark.poll()
				if tshark.returncode >= 0: break
				try:
					send_signal()
				except OSError:
					break
				else:
					time.sleep(0.5)
		#
	def dissect(self, nfpacket):
		"""
		Dissects a packet and returns a DissectedPacket instance or None if the
		dissector stopped during the dissection.

		  nfpacket -- an NFPacket instance to be dissected
		"""
		try:
			# packet timestamp
			current_time = time.time()
			sec = int(current_time)
			usec = int((current_time - sec) * 10**6)
			# build the pcap header
			pcap_header = struct.pack("I", sec)
			pcap_header += struct.pack("I", usec)
			pcap_header += struct.pack("I", len(nfpacket))
			pcap_header += struct.pack("I", len(nfpacket))
			pcap_data = pcap_header + str(nfpacket)
			# send the packet to tshark instances
			for mode in ["text", "pdml"]:
				self.__tshark[mode].stdin.write(pcap_data)
				self.__tshark[mode].stdin.flush()
			# get packet description
			description = self.__tshark["text"].stdout.readline().strip()
			# get pdml output
			pdml_packet = ""
			while True:
				line = self.__tshark["pdml"].stdout.readline()
				if not line: break
				line = line.strip()
				pdml_packet += line
				if line == "</packet>":
					findall = re.findall(
						".*(<packet>.*</packet>)", pdml_packet)
					if findall:
						pdml_packet = findall[0]
						break
			etree_packet = etree.parse(StringIO(pdml_packet)).getroot()
			return DissectedPacket(description, etree_packet)
		except IOError:
			if not self.__stopping.isSet():
				logging.error("error while sending data to tshark!")
				self.__ensure_is_running()
				return self.dissect(nfpacket)
			else:
				# program is stopping
				return None
		#
	def stop(self):
		""" Stops TShark instances properly. """
		if not self.__stopping.isSet():
			self.__stopping.set()
			self.__stop()
			logging.info("dissector stopped")
		#
	#

###############################################################################
# Classes (nfqueue)
###############################################################################

class NFPacket:
	""" A packet as it is captured by Netfilter. """
	def __init__(self, nfq_handle, nfq_data):
		"""
		Creates a new NFPacket instance.

		  nfq_handle -- Netfilter queue connection handle
		  nfq_data   -- Netlink packet data handle
		"""
		self.__nfq_handle = nfq_handle
		self.__nfq_data = nfq_data
		self.__packet_header = libnfq.get_full_msg_packet_hdr(nfq_data)
		self.__data_length, self.__data = libnfq.get_full_payload(nfq_data)
		#
	def __len__(self):
		""" Returns the packet length. """
		return self.__data_length
		#
	def __str__(self):
		""" Returns the packet bytes as a string. """
		return self.__data
		#
	def __set_verdict(self, verdict):
		""" Sets the verdict for this packet (ACCEPT or DROP). """
		libnfq.set_pyverdict(
			self.__nfq_handle,
			self.__packet_header["packet_id"],
			verdict,
			self.__data_length,
			self.__data
		)
		#
	def accept(self):
		""" Accepts the packet. """
		self.__set_verdict(libnfq.NF_ACCEPT)
		#
	def drop(self):
		""" Drops the packet. """
		self.__set_verdict(libnfq.NF_DROP)
		#
	#

class NFQueue(Thread):
	"""
	A Netfilter queue which receives packets, dissects them and makes them
	available to the Web interface.
	"""
	def __init__(self, queue_num):
		"""
		Creates a new NFQueue instance.

		  queue_num -- number of the Netfilter queue to listen
		"""
		Thread.__init__(self, name="NFQueueThread")
		self.__queue_num = queue_num
		self.__stopping = Event()
		self.__dissected_packets = []
		self.__dissector = Dissector()
		self.__dissector_stopping = Event()
		# set the queue parameters
		self.__snaplen = 65535
		self.__sock_family = socket.AF_INET
		self.__sock_type = 0
		# create the queue
		self.__nfq_handle = libnfq.open_queue()
		libnfq.unbind_pf(self.__nfq_handle, self.__sock_family)
		libnfq.bind_pf(self.__nfq_handle, self.__sock_family)
		# define a packet handler
		self.__c_handler = libnfq.HANDLER(self.__callback)
		self.__nfq_connection_handle = {}
		self.__nfq_connection_handle["queue"] = \
			libnfq.create_queue(
				self.__nfq_handle,
				self.__queue_num,
				self.__c_handler,
				None
			)
		libnfq.set_mode(
			self.__nfq_connection_handle["queue"],
			libnfq.NFQNL_COPY_PACKET,
			self.__snaplen
		)
		#
	def run(self):
		""" Waits packets from Netfilter. """
		# create a socket to receive packets
		s = socket.fromfd(
			libnfq.nfq_fd(libnfq.nfnlh(self.__nfq_handle)),
			self.__sock_family,
			self.__sock_type
		)
		s.settimeout(0.1)
		logging.info("nfqueue started")
		while not self.__stopping.isSet():
			try:
				data = s.recv(self.__snaplen)
			except:
				continue
			else:
				libnfq.handle_packet(self.__nfq_handle, data, len(data))
		# the queue is stopping
		libnfq.destroy_queue(self.__nfq_connection_handle["queue"])
		libnfq.close_queue(self.__nfq_handle)
		self.__dissector_stopping.set()
		logging.info("nfqueue stopped")
		#
	def stop(self):
		""" Stops the queue properly. """
		self.__stopping.set()
		self.__dissector_stopping.wait(1)
		self.__dissector.stop()
		#
	def __callback(self, dummy1, dummy2, nfq_data, dummy3):
		""" Handles the packets received from Netfilter. """
		nfpacket = NFPacket(self.__nfq_connection_handle["queue"], nfq_data)
		try:
			# packet processing
			dissected_packet = self.__dissector.dissect(nfpacket)
			if dissected_packet:
				self.__dissected_packets.append(dissected_packet)
			# TODO: add packet processing here!
			print dissected_packet
			nfpacket.accept()
		except Exception, exception:
			logging.debug(exception)
			nfpacket.accept()
		#
	#

###############################################################################
# Entry point
###############################################################################

def print_usage():
	sys.stderr.write(
"""Usage: %s [-v] [-q <queue_num>] [-t <tshark_binary>]

    -v                 : verbose mode, can be specified twice for debugging
    -q <queue_num>     : specify which netfilter queue must be used
    -t <tshark_binary> : path to tshark (default: bin/%s/tshark)

""" % (__file__, os.uname()[4]))
	#

if __name__ == "__main__":
	# defaults
	arg_queue_num = 0
	arg_tshark_binary = "bin/%s/tshark" % os.uname()[4]
	# setup logging
	verbose_level = sys.argv.count("-v")
	logging_level = [logging.ERROR, logging.INFO, logging.DEBUG][verbose_level]
	logging_format = (
		"%%(asctime)s %s proxyshark: [%%(levelname)s] %%(message)s" %
		socket.gethostname()
	)
	logging.basicConfig(level=logging_level, format=logging_format)
	# must be root
	if os.getuid() != 0:
		logging.error("permission denied")
		sys.exit(1)
	# parse the arguments
	try:
		opts, args = getopt.getopt(sys.argv[1:], "vq:t:")
	except getopt.GetoptError:
		print_usage()
		sys.exit(1)
	for opt, arg in opts:
		# -v
		if opt == "-v":
			pass
		# -q <queue_num>
		elif opt == "-q":
			if arg.isdigit() and int(arg) >= 0 and int(arg) <= 65535:
				arg_queue_num = int(arg)
			else:
				logging.error("invalid queue number")
				sys.exit(1)
		# -t <tshark_binary>
		elif opt == "-t":
			arg_tshark_binary = arg
		else:
			print_usage()
			sys.exit(1)
	if not os.path.exists(arg_tshark_binary):
		logging.error("file '%s' does not exist" % arg_tshark_binary)
		sys.exit(1)
	logging.info("queue number = %s" % arg_queue_num)
	logging.info("tshark binary = '%s'" % arg_tshark_binary)
	# run nfqueue and web server
	try:
		nfqueue = NFQueue(arg_queue_num)
		nfqueue.start()
	except Exception, exception:
		logging.error(exception)
	else:
		# infinite loop
		try:
			signal.signal(signal.SIGINT, handler_sigint)
			while nfqueue.isAlive():
				time.sleep(0.5)
		except KeyboardInterrupt:
			pass
		except Exception, exception:
			logging.error(exception)
		signal.signal(signal.SIGINT, signal.SIG_IGN)
	# stop the threads
	nfqueue.stop()
	#

