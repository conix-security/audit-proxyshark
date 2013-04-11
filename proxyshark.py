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

#TODO:
# - 'not' syntax in BPF filters
#

# can be overridden by command line arguments
verbose_level = 0

# ignore signals to let all the stuff load properly without user interrupt, we
# will re-enable signal handling later to intercept Ctrl-C and others
import signal
handler_sigint = signal.getsignal(signal.SIGINT)
signal.signal(signal.SIGINT, signal.SIG_IGN)

# imports

import binascii
import copy
import cProfile
import getopt
import json
import libnetfilter_queue as libnfq
import logging
import os
import pickle
import pstats
import random
import re
import readline
import rlcompleter
import socket
import stat
import string
import struct
import sys
import tempfile
import time
#import traceback

#from code import InteractiveConsole
from xml.etree.cElementTree import XMLParser

from BaseHTTPServer import *
from pyparsing import *
from SocketServer import *
from subprocess import *
from threading import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import (
    conf as scapy_conf,
    L3RawSocket,
    IP,
    TCP,
    send)

def cached(function):
    """Implements a generic caching decorator."""
    cache = {}
    def wrapper(*args):
        if args in cache:
            return cache[args]
        else:
            result = function(*args)
            cache[args] = result
            return result
    return wrapper
    #

def traceback(exception):
    """Prints the backtrace of an exception."""
    exc_type, _, exc_tb = sys.exc_info()
    exc_type = str(exc_type).partition("exceptions.")[2].rpartition("'>")[0]
    filename = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    logging.error("%s @%s:%s => %s" % (
        exc_type or 'UnknownException',
        filename,
        exc_tb.tb_lineno,
        str(exception)))
    #

@cached
def one_line(obj):
    """Returns the 1-line string representation of an object."""
    return re.sub(r' *\r*\n+ *', ' ', str(obj)).strip()
    #

# network devices
@cached
def network_devices():
    """Returns the available network interfaces."""
    fd = open('/proc/net/dev', 'r')
    result = ['-']
    for line in fd.readlines()[2:]:
        result.append(line.partition(':')[0].strip())
    fd.close()
    return result
    #

###############################################################################
# Test cases & Performance profiling
###############################################################################

stats = None

def profile(statement, env):
    """ TODO """
    global stats
    statement = "__profile__ = " + statement.replace("\n", "").strip()
    cProfile.runctx(statement, globals(), env, "proxyshark.stats")
    stats = pstats.Stats("proxyshark.stats")
    stats.sort_stats("time")
    stats.print_stats()
    return env["__profile__"]
    #

def profile_add(statement, env):
    """ TODO """
    global stats
    statement = "__profile__ = " + statement.replace("\n", "").strip()
    cProfile.runctx(statement, globals(), env, "proxyshark.stats")
    if stats:
        for i in xrange(10):
            stats.add("proxyshark.stats")
    else:
        stats = pstats.Stats("proxyshark.stats")
    return env["__profile__"]
    #

def profile_print(sig, frame):
    """ TODO """
    global stats
    stats.sort_stats("time")
    stats.print_stats()
    #

def testcase_dissection(sig, frame):
    """ TODO """
    global nfqueue
    def wrapper(d):
        for packet in nfqueue._cache.values():
            d.dissect(
                nfqueue._nfq_connection_handle["queue"],
                packet._nfq_data,
                packet.data
            )
    print "# Testcase: %s packet(s) in cache" % len(nfqueue._cache)
    d = Dissector()
    profile("wrapper(d)", locals())
    #

signal.signal(signal.SIGUSR1, testcase_dissection)
signal.signal(signal.SIGPROF, profile_print)

###############################################################################
# Classes (parsing)
###############################################################################

class BPF:
    """Provides static methods to parse BPF language and generate Netfilter
    rules from it."""
    prefix = 'PROXYSHARK'
    existing_chains = []
    @staticmethod
    def cleanup():
        """Removes all the Netfilter chains related to proxyshark."""
        logging.info("cleaning up chains")
        iptables = Popen(
            ['/sbin/iptables', '-L', '-n'],
            bufsize=-1,
            stdin=None,
            stdout=PIPE,
            stderr=None)
        findall = re.findall(
            r'\n(%s\d+) ' % BPF.prefix,
            iptables.stdout.read())
        if len(findall) > 0:
            chains = findall
            chains.reverse()
            # clean up default chains and flush proxyshark ones
            removed = []
            for chain in chains:
                if chain in removed:
                    continue
                for def_chain in ['INPUT', 'OUTPUT', 'FORWARD']:
                    BPF._iptables_raw('-t filter -D %s -j %s' % (
                        def_chain,
                        chain))
                BPF._iptables_raw('-t filter -F %s' % chain)
                removed.append(chain)
            # remove empty proxyshark chains
            removed = []
            for chain in chains:
                if chain in removed:
                    continue
                BPF._iptables_raw('-t filter -X %s' % chain)
                removed.append(chain)
        #
    @staticmethod
    def _new_chain_id():
        """Generates a new Netfilter chain identifier."""
        return BPF.__new_chain_id().next()
        #
    @staticmethod
    @cached
    def __new_chain_id():
        """Wrapper for the BPF._new_chain_id() method."""
        existing = []
        chain_id = None
        while 1:
            while not chain_id or chain_id in existing:
                chain_id = random.randint(1000, 9999)
                existing.append(chain_id)
                yield '%s%s' % (BPF.prefix, chain_id)
        #
    @staticmethod
    def _iptables_raw(args):
        """
        Executes a raw iptables command.

        args -- raw arguments to pass to iptables

        """
        # don't display the command if containing some particular arguments
        no_stderr = ''
        for no_display_arg in ['-N', '-D', '-F', '-X']:
            if ' %s ' % no_display_arg in args:
                no_stderr = ' 2> /dev/null'
                break
        else:
            global verbose_level
            if verbose_level > 1:
                logging.debug('iptables %s' % args)
        # execute the raw command with the given arguments
        os.system('/sbin/iptables %s%s' % (args, no_stderr))
        #
    @staticmethod
    def iptables(table, chain, bpf_filter, custom_args, targetname):
        """
        Generates and applies iptables rules from a given BPF filter.

        table       -- table in which to apply the rules
                       ('filter', 'nat', etc.)
        chain       -- chain in which to apply the rules
                       ('INPUT', 'OUTPUT', 'FORWARD', etc.)
        bpf_filter  -- BPF filter from which to generate the rules
        custom_args -- custom iptables arguments to append to the first
                       generated rule
        targetname  -- target of the last generated rule
                       ('ACCEPT', 'DROP', 'NFQUEUE', etc.)

        """
        # wrapper to process a given list of tokens
        def parse(tokens):
            rules = []
            # if we have a token list
            if isinstance(tokens[0], basestring):
                proto, direction, param, value = (
                    [None]*(4-len(tokens)) + list(tokens))
                if direction in ['icmp', 'tcp', 'udp']:
                    proto = direction
                    direction = None
                id0 = BPF._new_chain_id()
                id1 = BPF._new_chain_id()
                # any
                if value == 'any':
                    rules.append((id0, '', id1))
                # proto (without port)
                elif param is None:
                    rules.append((id0, '-p %s' % value, id1))
                # dev
                elif param in ['dev']:
                    if direction in [None, 'src']:
                        rules.append((id0, '-i %s' % value, id1))
                    if direction in [None, 'dst']:
                        rules.append((id0, '-o %s' % value, id1))
                # host
                elif param in ['host']:
                    if len(value) > 0 and value[0].isdigit():
                        values = [value]
                    else:
                        try:
                            values = resolver.query(value)
                        except:
                            values = [value]
                    for value in values:
                        if direction in [None, 'src']:
                            rules.append((id0, '-s %s' % value, id1))
                        if direction in [None, "dst"]:
                            rules.append((id0, '-d %s' % value, id1))
                # net
                elif param in ['net']:
                    if direction in ['src']:
                        rules.append((id0, '-s %s' % value, id1))
                    if direction in [None, "dst"]:
                        rules.append((id0, '-d %s' % value, id1))
                # port
                elif param in ['port']:
                    if proto:
                        proto_list = [proto]
                    else:
                        proto_list = ['tcp', 'udp']
                    for proto in proto_list:
                        if direction in [None, 'src']:
                            rules.append(
                                (id0, '-p %s --sport %s' % (proto, value), id1)
                            )
                        if direction in [None, 'dst']:
                            rules.append(
                                (id0, '-p %s --dport %s' % (proto, value), id1)
                            )
                else:
                    raise ParseException(repr(param))
            # if we have a single group
            elif len(tokens) == 1:
                rules = parse(tokens[0])
            # if we have a composition ('and' or 'or')
            elif len(tokens) == 3:
                if tokens[1] in ['and']:
                    rules0 = parse(tokens[0])
                    rules1 = parse(tokens[2])
                    for id0, rule, id1 in rules1:
                        if id0 == rules1[0][0]:
                            id0 = rules0[-1][-1]
                        if id1 == rules1[0][0]:
                            id1 = rules0[-1][-1]
                        rules.append((id0, rule, id1))
                    rules = rules0 + rules
                elif tokens[1] in ['or']:
                    rules0 = parse(tokens[0])
                    rules1 = parse(tokens[2])
                    for id0, rule, id1 in rules1:
                        if id0 == rules1[0][0]:
                            id0 = rules0[0][0]
                        elif id0 == rules1[-1][-1]:
                            id0 = rules0[-1][-1]
                        if id1 == rules1[0][0]:
                            id1 = rules0[0][0]
                        elif id1 == rules1[-1][-1]:
                            id1 = rules0[-1][-1]
                        rules.append((id0, rule, id1))
                    rules = rules0 + rules
            else:
                raise ParseException(repr(tokens))
            return rules
            #
        # process the bpf filter passed in argument
        if len(custom_args) > 0:
            custom_args = ' ' + custom_args.strip()
        # define a grammar to parse the bpf language
        direction = oneOf('src dst')
        dev = Optional(direction) + Literal('dev') + Word(alphanums)
        ip = Combine(
            Word(nums, max=3) + Literal('.') + Word(nums, max=3) +
            Literal('.') +
            Word(nums, max=3) + Literal('.') + Word(nums, max=3))
        hostname = Combine(Word(alphas) + Word(alphanums + '-._'))
        netmask = Literal('/') + Word(nums, max=2)
        host = Optional(direction) + Literal('host') + (ip | hostname)
        net = Optional(direction) + Literal('net') + Combine(ip + netmask)
        port = Optional(direction) + Literal('port') + Word(nums, max=5)
        proto = oneOf('icmp tcp udp') + Optional(port)
        logical = oneOf('and or')
        parser = Forward()
        parser << (
            Group(
                dev | proto | host | net | port |
                nestedExpr(content=parser)) +
            Optional(
                logical + Group(parser)))
        parser = (
            StringStart() +
            (Literal('any') | parser) +
            StringEnd())
        # parse the bpf filter
        logging.info('applying filter %s to chain %s' % (
            repr(bpf_filter or 'any'),
            repr(chain)))
        tokens = parser.parseString(bpf_filter or 'any')
        rules = parse(tokens)
        new_chains = list(set( # remove doubles
            [x[0] for x in rules] + [x[2] for x in rules]))
        for new_chain in new_chains:
            if new_chain not in BPF.existing_chains:
                BPF._iptables_raw('-t %s -N %s' % (
                    table,
                    new_chain))
                BPF.existing_chains.append(new_chain)
        BPF.existing_chains = list(set( # remove doubles
            BPF.existing_chains))
        BPF._iptables_raw('-t %s -I %s 1%s -j %s' % (
            table,
            chain,
            custom_args,
            rules[0][0]))
        for id0, rule, id1 in rules:
            if rule == '':
                # handler the 'any' case
                BPF._iptables_raw('-t %s -I %s 1 -j %s' % (
                    table,
                    id0,
                    targetname))
                break
            else:
                # general situation
                BPF._iptables_raw('-t %s -I %s 1 %s -j %s' % (
                    table,
                    id0,
                    rule,
                    id1))
        else:
            # not in the 'any' case
            BPF._iptables_raw('-t %s -I %s 1 -j %s' % (
                table,
                rules[-1][-1],
                targetname))
        #
    #

###############################################################################
# Classes (dissector)
###############################################################################

class DissectionException(Exception):
    pass
    #

class DissectedPacket:
    """
    A packet as seen by Wireshark and TShark (a tree structure composed of
    protocols and fields).

    nfq_handle   -- connection handle from the Netfilter queue
    nfq_data     -- Netlink packet data from the Netfilter queue
    description  -- packet descrition from TShark in text mode
    etree_packet -- etree.Element instance from a PDML <packet/> tag

    indev        -- input network interface
    outdev       -- output network interface
    data         -- raw data from Netfilter
    data_length  -- data length from Netfilter (should be equal to len(data))
    identifier   -- an integer which is guaranteed to be unique and constant
                    for this packet
    stream       -- packet stream identifier
    timestamp    -- arrival time
    source       -- source IP address
    destination  -- destination IP address
    protocol     -- highest protocol identified by TShark
    info         -- short packet summary

    verdict      -- packet destiny (NF_ACCEPT, NF_DROP or None)

    """
    def __init__(self, nfq_handle, nfq_data, description, etree_packet):
        """Creates a new instance."""
        # initialization
        self.nfq_handle = nfq_handle
        self.nfq_data = nfq_data
        full_msg_packet_hdr = libnfq.get_full_msg_packet_hdr(nfq_data)
        self.nfq_packet_id = full_msg_packet_hdr['packet_id']
        self.description = re.sub(r' +', ' ', description)
        self.etree_packet = etree_packet
        self.verdict = None
        # network interfaces
        self.indev = network_devices()[libnfq.get_indev(nfq_data)]
        self.outdev = network_devices()[libnfq.get_outdev(nfq_data)]
        # raw data
        self.data_length, self.data = libnfq.get_full_payload(nfq_data)
        # packet identifier
        try:
            items = self.__getitem__(
                'proto[@name="geninfo"]/field[@name="num"]/show')
            self.identifier = int(items[0])
        except IndexError:
            self.identifier = '?'
        except TypeError:
            self.identifier = '?'
        # packet stream
        try:
            items = self.__getitem__(
                'proto[@name="tcp"]/field[@name="tcp.stream"]/show')
            self.stream = int(items[0])
        except IndexError:
            self.stream = None
        except TypeError:
            self.stream = None
        # attributes from the description
        findall = re.findall(
            r'^(\d+.\d+) +([^ ]+) +-> +([^ ]+) +([^ ]+) +[^ ]+ +(.*)$',
            description)
        if len(findall) == 0 or len(findall[0]) != 5:
            raise ValueError(
                "invalid description '%s'" % one_line(description))
        try:
            self.timestamp = float(findall[0][0])
            self.source = findall[0][1]
            self.destination = findall[0][2]
            self.protocol = findall[0][3]
            self.info = findall[0][4]
        except IndexError:
            raise ValueError(
                "invalid description '%s'" % one_line(description))
        except TypeError:
            raise ValueError(
                "invalid description '%s'" % one_line(description))
        #
    def __str__(self):
        """Returns the packet as a well-formatted string."""
        result = "Packet #%s" % self.identifier
        if self.stream is not None:
            result += " (stream %s)" % self.stream
        result += ", %s" % self.description
        return result
        #
    def _set_verdict(self, verdict):
        """Sets the verdict (NF_ACCEPT or NF_DROP)."""
        if self.verdict:
            raise IOError("verdict already set")
        libnfq.set_pyverdict(
            self.nfq_handle,
            self.nfq_packet_id,
            verdict,
            self.data_length,
            self.data)
        self.verdict = verdict
        #
    def accept(self):
        """Accepts the packet."""
        self._set_verdict(libnfq.NF_ACCEPT)
        #
    def drop(self):
        """Drops the packet."""
        self._set_verdict(libnfq.NF_DROP)
        #
    def __getitem__(self, key):
        """Returns fields from a given XPath key."""
        items = self.etree_packet.findall(key)
        if items == []:
            key, _, attr_name = key.rpartition('/')
            items = self.etree_packet.findall(key)
            if items == []:
                return []
            else:
                return [item.get(attr_name) for item in items]
        else:
            result = []
            for item in items:
                d = {}
                for k, v in item.items():
                    d[k] = v
                result.append(d)
            return result
        #
    #

class Dissector:
    """A packet dissector based on TShark."""
    def __init__(self, quiet=False):
        """
        Runs two instances of TShark: one in text mode (-T text) to get general
        packet descriptions and one in PDML mode (-T pdml) to get complete
        packet dissections.

        quiet -- if True, don't print any information about the dissector state

        """
        self._quiet = quiet
        self._stopping = Event()
        # use the tshark binary given in argument
        global arg_tshark_dir
        tshark_path = os.path.join(os.getcwd(), arg_tshark_dir, 'tshark')
        # provide tshark with a global pcap header
        pcap_global_header = (
            '\xd4\xc3\xb2\xa1' # magic number
            '\x02\x00'         # major version
            '\x04\x00'         # minor version
            '\x00\x00\x00\x00' # gmt-to-local correction
            '\x00\x00\x00\x00' # accuracy of timestamps
            '\xff\xff\x00\x00' # snaplen
            '\x65\x00\x00\x00' # data link type
        )
        # tshark settings
        settings = []
        for name, value in [
            ('tcp.analyze_sequence_numbers',  True),
            ('tcp.calculate_timestamps',      True),
            ('tcp.check_checksum',            True),
            ('tcp.desegment_tcp_streams',     False),
            ('tcp.relative_sequence_numbers', True),
            ('tcp.summary_in_tree',           True),
            ('tcp.track_bytes_in_flight',     True),
            ('tcp.try_heuristic_first',       True),
            ('udp.check_checksum',            True),
            ('udp.process_info',              True),
            ('udp.summary_in_tree',           True),
            ('udp.try_heuristic_first',       True),
        ]:
            settings.append("-o %s:%s" % (name, str(value).upper()))
        # run tshark instances
        self._tshark = {}
        for mode in ['text', 'pdml']:
            cmdline = '%s -i - -s0 -n -l -T %s %s' % (
                tshark_path, mode, ''.join(settings))
            self._tshark[mode] = Popen(
                cmdline.split(' '),
                bufsize=-1,
                stdin=PIPE,
                stdout=PIPE,
                stderr=PIPE)
            self._tshark[mode].stdin.write(pcap_global_header)
            self._tshark[mode].stdin.flush()
            time.sleep(0.5)
            self._tshark[mode].poll()
            if self._tshark[mode].returncode >= 0:
                raise RuntimeError("running tshark in %s mode failed" % mode)
            self._tshark[mode].stderr.close()
        if not self._quiet:
            logging.info("dissector started")
        #
    #def _ensure_is_running(self, restart_attempts=None):
    #    """Ensures that TShark is running and tries to restart it if
    #    necessary."""
    #    max_restart_attempts = 3
    #    if restart_attempts is None:
    #        restart_attempts = max_restart_attempts
    #    # check if tshark is running
    #    for mode in ['text', 'pdml']:
    #        self._tshark[mode].poll()
    #        if self._tshark[mode].returncode >= 0:
    #            break
    #    # still running, quit
    #    else:
    #        return
    #    # not running, try to restart it
    #    if not self._stopping.isSet():
    #        self._stop()
    #        if restart_attempts:
    #            if not self._quiet:
    #                logging.info("restarting dissector...")
    #            time.sleep((1 + max_restart_attempts - restart_attempts)**2)
    #            self.__init__()
    #            self._ensure_is_running(restart_attempts - 1)
    #        else:
    #            raise RuntimeError(
    #                "tshark is not running and cannot be restarted")
    #    #
    def _stop(self):
        """Stops TShark instances properly."""
        for mode in ['text', 'pdml']:
            tshark = self._tshark[mode]
            for send_signal in [tshark.terminate, tshark.kill]:
                tshark.poll()
                if tshark.returncode >= 0:
                    break
                try:
                    send_signal()
                except OSError:
                    break
                else:
                    time.sleep(0.5)
        #
    def dissect(self, nfq_handle, nfq_data):
        """
        Returns a tuple composed of a short description and an etree.Element
        instance describing the packet given in argument.

        nfq_handle -- connection handle from the Netfilter queue
        nfq_data   -- Netlink packet data from the Netfilter queue

        """
        try:
            # raw data
            data_length, data = libnfq.get_full_payload(nfq_data)
            # packet timestamp
            current_time = time.time()
            sec = int(current_time)
            usec = int((current_time - sec) * 1000000)
            # create a pcap header
            pcap_header = struct.pack('I', sec)
            pcap_header += struct.pack('I', usec)
            pcap_header += struct.pack('I', data_length)
            pcap_header += struct.pack('I', data_length)
            pcap_data = pcap_header + data
            # send the packet to tshark
            for mode in ['text', 'pdml']:
                self._tshark[mode].stdin.write(pcap_data)
                self._tshark[mode].stdin.flush()
            # retrieve the packet description and the xml dissection
            parser = XMLParser()
            xml = []
            parser_feed = lambda line: None
            while 1:
                line = self._tshark['pdml'].stdout.readline()
                if line is None:
                    raise DissectionException("unexpected end of file!")
                if line == '<packet>\n':
                    parser_feed = xml.append
                parser_feed(line)
                if line == '</packet>\n':
                    parser.feed(''.join(xml))
                    break
            description = self._tshark['text'].stdout.readline()[2:-1]
            etree_packet = parser.close()
            return description, etree_packet
        except IOError:
            return None, None
        #
    def stop(self):
        """Stops TShark instances properly."""
        if not self._stopping.isSet():
            self._stopping.set()
            self._stop()
            if not self._quiet:
                logging.info("dissector stopped")
        #
    #

###############################################################################
# Classes (nfqueue)
###############################################################################

class NFQueue(Thread):
    """A Netfilter queue to receive packets, dissect them and make them
    available to the user interface."""
    #
    def __init__(self, queue_num, bpf_filter, xpath_filter, web_server=None):
        """
        Creates a new instance.

        queue_num    -- queue to listen
        bpf_filter   -- bpf-filter describing the packets to capture
        xpath_filter -- xpath filter describing the packets to process
        web_server   -- a WebServer instance to host the local web services

        """
        # initialization
        Thread.__init__(self, name='NFQueueThread')
        self.queue_num = queue_num
        self.bpf_filter = bpf_filter
        self.xpath_filter = xpath_filter
        self.packets = {}
        self.streams = {}
        self._dissector = Dissector()
        self._web_server = web_server
        # setup the bpf filter
        BPF.cleanup()
        for chain in ['INPUT', 'OUTPUT', 'FORWARD']:
            BPF.iptables(
                'filter',
                chain,
                bpf_filter,
                '',
                'NFQUEUE --queue-num %s' % queue_num)
        # events
        self._stopping = Event()
        self._dissector_stopping = Event()
        # set the queue parameters
        self._snaplen = 65535
        self._sock_family = socket.AF_INET
        self._sock_type = 0
        # create the queue
        self._nfq_handle = libnfq.open_queue()
        libnfq.unbind_pf(self._nfq_handle, self._sock_family)
        libnfq.bind_pf(self._nfq_handle, self._sock_family)
        self._c_handler = libnfq.HANDLER(self._callback)
        self._nfq_connection_handle = {}
        self._nfq_connection_handle['queue'] = libnfq.create_queue(
            self._nfq_handle,
            self.queue_num,
            self._c_handler,
            None)
        libnfq.set_mode(self._nfq_connection_handle['queue'],
                        libnfq.NFQNL_COPY_PACKET,
                        self._snaplen)
        #
    def run(self):
        """Waits for packets from Netfilter."""
        # create a socket to receive packets
        s = socket.fromfd(
            libnfq.nfq_fd(libnfq.nfnlh(self._nfq_handle)),
            self._sock_family,
            self._sock_type)
        s.settimeout(0.1)
        logging.info("nfqueue started")
        while not self._stopping.isSet():
            try:
                data = s.recv(self._snaplen)
            except:
                continue
            else:
                libnfq.handle_packet(self._nfq_handle, data, len(data))
        # the queue is stopping
        libnfq.destroy_queue(self._nfq_connection_handle['queue'])
        libnfq.close_queue(self._nfq_handle)
        self._dissector_stopping.set()
        logging.info("nfqueue stopped")
        #
    def stop(self):
        """Stops the queue properly."""
        self._stopping.set()
        self._dissector_stopping.wait(1)
        self._dissector.stop()
        BPF.cleanup()
        #
    def _callback(self, dummy1, dummy2, nfq_data, dummy3):
        """Handles the packets received from Netfilter."""
        try:
            # packet dissection
            description, etree_packet = self._dissector.dissect(
                self._nfq_connection_handle['queue'],
                nfq_data)
            if description != None and etree_packet != None:
                packet = DissectedPacket(
                    self._nfq_connection_handle['queue'],
                    nfq_data,
                    description,
                    etree_packet)
                global verbose_level
                if verbose_level > 0: # quiet mode
                    sys.stderr.write(str(packet) + '\n')
                if verbose_level > 1: # verbose mode
                    pass #TODO: add detailed description here

                

                # storage
                #self.packets[packet.identifier] = packet
                #if packet.stream is not None:
                #    self.streams.setdefault(packet.stream, []).append(packet)
                #TODO: processing
                packet.accept()
                #packet.drop()
        except Exception, exception:
            traceback(exception)
            full_msg_packet_hdr = libnfq.get_full_msg_packet_hdr(nfq_data)
            nfq_packet_id = full_msg_packet_hdr['packet_id']
            data_length, data = libnfq.get_full_payload(nfq_data)
            libnfq.set_pyverdict(
                self._nfq_connection_handle['queue'],
                nfq_packet_id,
                libnfq.NF_ACCEPT,
                data_length,
                data)
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
        #
    #

###############################################################################
# Classes (web server)
###############################################################################

class ThreadingWebServer(ThreadingMixIn, HTTPServer):
    """Web server with multi-threading support for incoming connections."""
    pass

class WebServer(Thread):
    """A small web server to receive its own traffic composed of HTTP-embedded
    captured packets."""
    def __init__(self, proxy_addr, proxy_port, ws_addr, ws_port):
        """
        Creates a new instance.

        proxy_addr -- address of the remote web proxy
        proxy_port -- port of the remote web proxy
        ws_addr -- bind address for the local web server
        ws_port -- local port for client connections on the web services

        """
        Thread.__init__(self, name='WebProxyThread')
        self._proxy_addr = proxy_addr
        self._proxy_port = proxy_port
        self._ws_addr = ws_addr
        self._ws_port = ws_port
        self._server = None
        #
    def run(self):
        """Starts the web server."""
        try:
            self._server = ThreadingWebServer(
                (self._ws_addr, self._ws_port),
                WebRequestHandler)
            logging.info("local server listening on %s:%s" % (
                self._ws_addr, self._ws_port))
            self._server.serve_forever()
            self._server.socket.close()
        except Exception, exception:
            traceback(exception)
        finally:
            logging.info("server stopped")
        #
    def stop(self):
        """Stops the web server properly."""
        try:
            if self._server:
                self._server.shutdown()
        except AttributeError:
            pass
        #
    #

class WebRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests."""
    lastlog = {'line': '', 'nb': 0}
    #
    def address_string(self):
        """Bypasses default address resolution."""
        return self.client_address[:2][0]
        #
    def do_GET(self):
        """Handles GET requests."""
        self.method = 'GET'
        self.send_not_found()
        #
    def do_POST(self):
        """Handles POST requests."""
        self.method = 'POST'
        self.handler_request()
        #
    def handler_request(self):
        """Generic request handler."""
        currentThread().setName('WebRequestHandlerThread')
        # get path and parameters from the request
        findall = re.findall(r'^/+([^?]*)(\?.*)?$', self.path)
        if len(findall) == 0:
            self.send_not_found()
            return
        # path
        self.path = os.path.normpath(findall[0][0])
        current_dir = os.path.realpath(os.getcwd())
        if not os.path.realpath(self.path).startswith(current_dir):
            self.send_not_found()
            return
        if self.path == '.':
            if self.method == 'GET':
                self.path = 'index.html'
            else:
                self.path = ''
        self.path = '/' + self.path
        # parameters
        self.params = {}
        findall = re.findall(r'([a-z_]+)=([^&]+)', findall[0][1])
        if len(findall) > 0:
            for param, value in findall:
                self.params[param] = value
        # ajax request
        if self.is_ajax():
            # just for indentation
            if 0: pass
            # /edit-packet
            elif self.path == '/edit-packet':
                self.edit_packet()
            else:
                self.send_not_found()
        # file request
        elif False: # disabled
            # validate the extension
            extension = self.path.rpartition('.')[2]
            if not extension in ['css', 'gif', 'html', 'js']:
                self.send_not_found()
                return
            # open the local file
            try:
                fd = open(os.path.join('www', self.path), 'r')
            except IOError:
                self.send_not_found()
            else:
                # send the response headers
                self.send_response(200, 'OK')
                mime = {
                    'css': 'text/css',
                    'gif': 'image/gif',
                    'html': 'text/html',
                    'js': 'application/javascript'
                }
                self.send_header('Content-Type', mime[extension])
                self.end_headers()
                # senf the file
                self.wfile.write(fd.read())
                fd.close()
        else:
            self.send_not_found()
        #
    def is_ajax(self):
        """Returns True if the current request was made in AJAX."""
        return ('X-Requested-With' in self.headers and
                self.headers['X-Requested-With'] == 'XMLHttpRequest')
        #
    def log_request(self, code):
        """Logs the current request."""
        # build the new log line
        if not hasattr(self, 'params'):
            self.params = {}
        log_line = "%s %s %s %s %s" % (
            self.client_address[0],
            self.method,
            self.path,
            self.params,
            code)
        # get the last log line
        lastlog = WebRequestHandler.lastlog
        # again the same log line?
        def cleanup_log(line):
            return re.subn(r'\'_dc\': \'\d+\'', '', line)[0]
        if cleanup_log(log_line) == cleanup_log(lastlog['line']):
            lastlog['nb'] += 1
        # print the new log line
        else:
            if lastlog['nb'] > 0:
                logging.info("[repeat x%s]" % lastlog['nb'])
            logging.info(log_line)
            lastlog['line'] = log_line
            lastlog['nb'] = 0
        WebRequestHandler.lastlog = lastlog
        #
    def send_not_found(self):
        """Sends a 404 NOT FOUND."""
        self.send_response(404, 'NOT FOUND')
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        #
    def edit_packet(self):
        """"""
        self.send_response(200, 'OK')
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        #
    #

###############################################################################
# Entry point
###############################################################################

def print_usage():
    usage = """Usage: %s [-h] [-v [-v]] [-t <tshark-dir>] [-q <queue-num>] [-w <proxy-addr>:<proxy-port>:<ws-addr>:<ws-port>] [-b <bpf-filter>] [-x <xpath-filter>]

        -h : print this help and quit

        -v : verbose mode, can be specified twice for debugging mode (default is quiet mode)

        -t : location of the tshark binary to use (default is './bin/%s/')

        -q : queue number to use (default is 1234)

        -w : web-driven mode (local port for the web services and proxy to use to join them)

        -b : bpf-filter describing the packets to capture

        -x : xpath filter describing the packets to process


    For example, if you want to intercept SIP traffic in web-driven mode using Burp Suite on port 8080:

        root@debian:~$ %s -w 127.0.0.1:8080:127.0.0.1:1234 -b 'udp port 5060' -x 'proto[@name="sip"]'

    """
    sys.stdout.write(usage % (__file__, os.uname()[4], __file__))
    sys.stdout.write('\n')
    #

if __name__ == '__main__':
    # defaults
    arg_tshark_dir = 'bin/%s/' % os.uname()[4]
    arg_queue_num = 1234
    arg_web_driven = False
    arg_proxy_addr = None
    arg_proxy_port = None
    arg_ws_addr = None
    arg_ws_port = None
    arg_bpf_filter = None
    arg_xpath_filter = None
    # setup logging
    verbose_level = sys.argv.count('-v')
    logging_level = [logging.ERROR, logging.INFO, logging.DEBUG][verbose_level]
    logging_format = (
        "%%(asctime)s %s proxyshark: [%%(levelname)s] %%(message)s" %
        socket.gethostname())
    logging.basicConfig(level=logging_level, format=logging_format)
    # must be root
    if os.getuid() != 0:
        logging.error("permission denied")
        sys.exit(1)
    # parse the arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hvt:q:w:b:x:')
    except getopt.GetoptError:
        print_usage()
        sys.exit(1)
    for opt, arg in opts:
        # -h
        if opt == '-h':
            print_usage()
            sys.exit(1)
        # -v
        elif opt == '-v':
            pass
        # -t <tshark-dir>
        elif opt == '-t':
            arg_tshark_dir = arg
        # -q <queue-num>
        elif opt == '-q':
            if arg.isdigit() and int(arg) >= 0 and int(arg) <= 65535:
                arg_queue_num = int(arg)
            else:
                logging.error("invalid queue number")
                sys.exit(1)
        # -w <proxy-addr>:<proxy-port>:<ws-addr>:<ws-port>
        elif opt == '-w':
            arg_web_driven = True
            split = arg.split(':')
            if len(split) == 4:
                # proxy address
                try:
                    socket.inet_aton(split[0])
                    arg_proxy_addr = split[0]
                except:
                    logging.error("invalid proxy address")
                    sys.exit(1)
                # proxy port
                if (split[1].isdigit() and
                    int(split[1]) > 0 and int(split[1]) <= 65535
                ):
                    arg_proxy_port = int(split[1])
                else:
                    logging.error("invalid proxy port")
                    sys.exit(1)
                # local address for the web services
                try:
                    socket.inet_aton(split[2])
                    arg_ws_addr = split[2]
                except:
                    logging.error("invalid local address for the web services")
                    sys.exit(1)
                # local port for the web services
                if (split[3].isdigit() and
                    int(split[3]) > 0 and int(split[3]) <= 65535
                ):
                    arg_ws_port = int(split[3])
                else:
                    logging.error("invalid local port for the web services")
                    sys.exit(1)
            else:
                logging.error("invalid proxy / web services specification")
                sys.exit(1)
        # -b <bpf-filter>
        elif opt == '-b':
            arg_bpf_filter = arg
        # -x <xpath-filter>
        elif opt == '-x':
            arg_xpath_filter = arg
        else:
            print_usage()
            sys.exit(1)
    if not os.path.exists(arg_tshark_dir):
        logging.error("directory %s does not exist" % repr(arg_tshark_dir))
        sys.exit(1)
    if verbose_level == 0:
        sys.stderr.write("Running in quiet mode (use -h for help)...\n")
    logging.info("tshark directory = %s" % repr(arg_tshark_dir))
    logging.info("queue number = %s" % arg_queue_num)
    if arg_web_driven:
        logging.info("web proxy = %s:%s" % (arg_proxy_addr, arg_proxy_port))
        logging.info("web services = %s:%s" % (arg_ws_addr, arg_ws_port))
    else:
        logging.info("web proxy = None")
        logging.info("web services = None")
    logging.info("bpf filter = %s" % repr(arg_bpf_filter))
    logging.info("xpath_filter = %s" % repr(arg_xpath_filter))
    # run the web server if necessary
    try:
        if arg_web_driven:
            web_server = WebServer(
                arg_proxy_addr, arg_proxy_port,
                arg_ws_addr, arg_ws_port)
            web_server.start()
        else:
            web_server = None
    except Exception, exception:
        logging.error(exception)
        sys.exit(1)
    # run nfqueue
    try:
        nfqueue = NFQueue(
            arg_queue_num,
            arg_bpf_filter,
            arg_xpath_filter,
            web_server)
        nfqueue.start()
    except Exception, exception:
        logging.error(exception)
        if arg_web_driven:
            web_server.stop()
        sys.exit(1)
    else:
        # infinite loop
        try:
            signal.signal(signal.SIGINT, handler_sigint)
            while nfqueue.isAlive():
                if arg_web_driven and not web_server.isAlive():
                    break
                time.sleep(0.5)
            time.sleep(1)
        except KeyboardInterrupt:
            pass
        except Exception, exception:
            logging.error(exception)
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except KeyboardInterrupt:
            pass
        # stop the threads
        if arg_web_driven:
            web_server.stop()
        nfqueue.stop()
    logging.info("done.")
    sys.exit(0)
    #

