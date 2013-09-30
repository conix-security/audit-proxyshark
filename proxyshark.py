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
# MERCHANTABILITY or FITNESSA PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

__version__ = '1.0b'

__banner__ = "Welcome to Proxyshark (%s)" % __version__

# ignore signals to let all the stuff load properly without user interrupt, we
# will re-enable signal handling later to intercept Ctrl-C (SIGINT)
import signal
handler_sigint = signal.getsignal(signal.SIGINT)
signal.signal(signal.SIGINT, signal.SIG_IGN)

# imports

import binascii
import copy
import cProfile
import getopt
import gzip
import httplib
import libnetfilter_queue as libnfq # need python-nfqueue
import logging
import os
import pstats
import random
import re
import readline
import rlcompleter
import socket
import string
import StringIO
import struct
import sys
import time
import traceback
import urllib

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from code import InteractiveConsole
try:
    from dns import resolver # need python-dnspython
except ImportError:
    pass
from pyparsing import (alphas, alphanums, Combine, Empty, Forward, Group,
                       Keyword, nestedExpr, NotAny, nums, oneOf, opAssoc,
                       operatorPrecedence, Optional, ParseException,
                       ParseResults, quotedString, StringEnd, StringStart,
                       Suppress, White, Word) # need python-pyparsing
alphanums += '-._'
from SocketServer import ThreadingMixIn
from subprocess import Popen, PIPE
from threading import currentThread, Event, RLock, Thread
from xml.etree.cElementTree import XMLParser

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import conf as scapy_conf, L3RawSocket, IP, TCP, UDP, send

def cached(function):
    """Implements a generic caching decorator."""
    cache = {}
    def wrapper(*args):
        key = args # note that the key must be hashable
        if key in cache:
            return cache[key]
        result = function(*args)
        cache[key] = result
        return result
    return wrapper
    #

_not_concurrent_lock = RLock()
def not_concurrent(function):
    """Ensures that a given function can't be called concurrently."""
    global _not_concurrent_lock
    def wrapper(*args):
        _not_concurrent_lock.acquire()
        result = function(*args)
        _not_concurrent_lock.release()
        return result
    return wrapper
    #

###############################################################################
# Cached versions of usual functions
###############################################################################

@cached
def re_compile(pattern, flags=0):
    """Provides a cached version of 're.compile()'."""
    return re.compile(pattern, flags)
    #

# shortcut
r = re_compile

###############################################################################
# Logging
###############################################################################

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

COLORS = {
    'WARNING'  : YELLOW,
    'INFO'     : WHITE,
    'DEBUG'    : BLUE,
    'CRITICAL' : YELLOW,
    'ERROR'    : RED,
    'RED'      : RED,
    'GREEN'    : GREEN,
    'YELLOW'   : YELLOW,
    'BLUE'     : BLUE,
    'MAGENTA'  : MAGENTA,
    'CYAN'     : CYAN,
    'WHITE'    : WHITE,
}

RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ  = "\033[1m"

class ColorFormatter(logging.Formatter):
    """Implements colored output for the logging module."""
    def __init__(self, *args, **kwargs):
        """Creates a new instance."""
        # can't do super(...) here because Formatter is an old school class
        logging.Formatter.__init__(self, *args, **kwargs)
        #
    def format(self, record):
        """Formats a given record with the appropriate colors."""
        levelname = record.levelname
        color     = COLOR_SEQ % (30 + COLORS[levelname])
        message   = logging.Formatter.format(self, record)
        message   = message.replace("$RESET", RESET_SEQ)
        message   = message.replace("$BOLD",  BOLD_SEQ)
        message   = message.replace("$COLOR", color)
        for k, v in COLORS.items():
            message = message.replace("$" + k,    COLOR_SEQ % (v+30))
            message = message.replace("$BG" + k,  COLOR_SEQ % (v+40))
            message = message.replace("$BG-" + k, COLOR_SEQ % (v+40))
        return message + RESET_SEQ
        #
    #

@not_concurrent
def _logging_exception(exception):
    """Prints an exception."""
    # retrieve information about the exception
    exc_type, _, exc_tb = sys.exc_info()
    exc_type = str(exc_type).partition('exceptions.')[2].rpartition('\'>')[0]
    stack = traceback.extract_tb(exc_tb)
    stack.reverse()
    for filename, lineno, _, _ in stack:
        if filename == __file__:
            break
    else:
        filename, lineno, _, _ = stack[0]
    logging_error("%s@%s:%s => %s"
                  % (exc_type or 'Exception',
                     filename,
                     lineno,
                     str(exception)))
    # print backtrace only in debug mode
    if verbose_level > 1:
        for filename, lineno, _, line in stack:
            logging_error("- %s:%-4s => %s"
                          % (filename,
                             lineno,
                             line))
    #

@not_concurrent
def _logging_print(string):
    """Prints a raw string to stderr."""
    sys.stderr.write("\033[37m%s\033[0m\n" % string)
    #

# shortcuts (performance tip)
logging_debug     = not_concurrent(logging.debug)
logging_info      = not_concurrent(logging.info)
logging_warning   = not_concurrent(logging.warning)
logging_error     = not_concurrent(logging.error)
logging_exception = _logging_exception
logging_print     = _logging_print

def cleanup_log_line(string):
    """Removes unwanted parts of a given log line."""
    return r(r'\'_dc\': \'\d+\'').subn('', string)[0]
    #

def one_line(obj):
    """Returns the 1-line string representation of an object."""
    return r(r' *\r*\n+ *').sub(' ', str(obj)).strip()
    #

def truncated(string, max_length=50):
    """Returns the truncated value of a string."""
    default = str(string)
    if len(default) > max_length:
        result = '%s...' % default[:max_length-3].strip()
    else:
        result = default
    return result
    #

def trunc_repr(string, max_length=50):
    """Returns the truncated representation of a string."""
    default = repr(string)
    if len(default) > max_length:
        result = '%s...\'' % default[:max_length-4].strip()
    else:
        result = default
    return result
    #

def logging_disable():
    """Temporarily disable logging."""
    global verbose_level, real_verbose_level
    real_verbose_level = verbose_level
    logging.disable(logging.ERROR)
    verbose_level = 0
    #

def logging_enable():
    """Enable logging."""
    global verbose_level, real_verbose_level
    verbose_level = real_verbose_level
    logging.disable(logging.NOTSET)
    #

def save_history():
    """Saves history to disk."""
    history_path = os.path.expanduser('~/.proxyshark_history')
    readline.write_history_file(history_path)
    #

def load_history():
    """Loads history from disk."""
    history_path = os.path.expanduser('~/.proxyshark_history')
    if os.path.exists(history_path):
        readline.read_history_file(history_path)
    #

###############################################################################
# Utilities
###############################################################################

#@cached
def check_tokens(tokens, types_and_values):
    """Checks if the given tokens are of a given type and value. Returns the
    number of tokens that match."""
    try:
        re_search = r(r'\bclass\b|\btype\b').search
        for token, types_and_values in zip(tokens, types_and_values):
            if re_search(repr(types_and_values)):
                if not isinstance(token, types_and_values):
                    return 0
            else:
                if token != types_and_values:
                    return 0
        return len(tokens)
    except TypeError:
        return 0
    #

@cached
def network_devices(n=None):
    """Returns the name of the nth network interface."""
    # get the device list from 'ip a'
    devices = ['-']
    ip_a = Popen(['ip', 'a'], bufsize=-1, stdin=None, stdout=PIPE, stderr=None)
    for line in ip_a.stdout.readlines():
        findings = r(r'^[0-9]+: *([^:]+):').findall(line)
        if findings:
            devices.append(findings[0])
    ip_a.stdout.close()
    # return either the entire list or the nth device
    if n is None:
        result = devices
    elif len(devices) > n:
        result = devices[n]
    else:
        result = '-'
    return result
    #

###############################################################################
# Test cases & Performance profiling
###############################################################################

stats = None

def profile(statement, env):
    """Runs the given piece of code and prints profiling statistics."""
    global stats
    statement = '__profile__ = %s' % one_line(statement)
    cProfile.runctx(statement, globals(), env, 'proxyshark.stats')
    stats = pstats.Stats('proxyshark.stats')
    stats.sort_stats('tottime')
    stats.print_stats()
    return env['__profile__']
    #

def profile_add(statement, env):
    """Runs the given piece of code and store profiling statistics."""
    global stats
    statement = '__profile__ = %s' % one_line(statement)
    cProfile.runctx(statement, globals(), env, 'proxyshark.stats')
    if stats:
        for i in range(100):
            stats.add('proxyshark.stats')
    else:
        stats = pstats.Stats('proxyshark.stats')
    return env['__profile__']
    #

def profile_print(sig, frame):
    """Prints profiling statistics stored with 'profile_add()'."""
    global stats
    stats.sort_stats('tottime')
    stats.print_stats()
    #

# print profiling statistics when receiving SIGPROF
signal.signal(signal.SIGPROF, profile_print)

###############################################################################
# Classes (Netfilter rules)
###############################################################################

class Netfilter:
    """Provides static methods to manage Netfilter rules."""
    _chain_prefix = 'PROXYSHARK'
    _existing_chains = []
    # Public methods ##########################################################
    @staticmethod
    def apply_capture_filter(capture_filter, queue_num):
        """Generates and applies Netfilter rules from a given BPF filter. A
        rule is composed of a chain, a condition (iptables syntax) and a
        target. Rules are added to the 3 main Netfilter chains INPUT, OUTPUT
        and FORWARD with target 'NFQUEUE --queue-num <queue_num>'."""
        # create rules from the bpf filter
        logging_info("parsing capture filter %s" % trunc_repr(capture_filter))
        parser = Netfilter._capture_filter_parser()
        tokens = parser.parseString(capture_filter)
        rules = Netfilter._process_boolean(tokens, Netfilter._process_keyword)
        # we must have at least one rule
        if not rules:
            chain = Netfilter._new_chain_id()
            target = Netfilter._new_chain_id()
            rules = [(chain, '', target)]
        # apply the rules
        table = 'filter'
        last_target = 'NFQUEUE --queue-num %s' % queue_num
        for first_chain in ('INPUT', 'OUTPUT', 'FORWARD'):
            Netfilter._apply_rules(table, first_chain, rules, last_target)
        #
    @staticmethod
    def remove_rules():
        """Removes all Netfilter rules and chains related to Proxyshark."""
        logging_info("removing custom Netfilter rules")
        # retrieve the proxyshark chains
        iptables = Popen(['iptables', '-L', '-n'],
                         bufsize=-1,
                         stdin=None,
                         stdout=PIPE,
                         stderr=None)
        regex = r'\n(?:Chain )?(%s\d+) ' % Netfilter._chain_prefix
        existing_chains = r(regex).findall(iptables.stdout.read())
        if not existing_chains:
            return
        # for each existing proxyshark chain
        for current_chain in tuple(set(existing_chains)):
            # remove the rules that have the current chain as a target
            Netfilter_raw_iptables = Netfilter._raw_iptables
            for main_chain in ('INPUT', 'OUTPUT', 'FORWARD'):
                args = '-t filter -D %s -j %s' % (main_chain, current_chain)
                Netfilter_raw_iptables(args)
            # flush the current chain
            Netfilter._raw_iptables('-t filter -F %s' % current_chain)
        # remove empty chains
        Netfilter_raw_iptables = Netfilter._raw_iptables
        for current_chain in existing_chains:
            Netfilter_raw_iptables('-t filter -X %s' % current_chain)
        #
    # Built-in methods ########################################################
    #
    # Private methods #########################################################
    @staticmethod
    @cached # the generator is cached, but not '_next_chain_id()' (see below)
    def __new_chain_id():
        """Returns a generator of random Netfilter chain identifiers."""
        chain_id = None
        existing_chains = []
        while 1:
            while not chain_id or chain_id in existing_chains:
                chain_id = ''.join((Netfilter._chain_prefix,
                                    str(random.randint(1000, 9999))))
                existing_chains.append(chain_id)
                yield chain_id
        #
    @staticmethod
    def _new_chain_id():
        """Generates a new unique and random Netfilter chain identifier."""
        return Netfilter.__new_chain_id().next()
        #
    @staticmethod
    @cached
    def _capture_filter_parser():
        """Creates a parser for the BPF language."""
        # handle boolean expressions ('not', 'and', 'or')
        def Boolean(clause, clause_can_be_a_keyword=False):
            # we need the second argument to handle the case where a value
            # begins like a reserved keyword (for example a hostname begining
            # with the substring 'and')
            if not clause_can_be_a_keyword:
                keywords = ('not and or in out src dst '
                            'dev host net port ip icmp tcp udp')
                clause = NotAny(oneOf(keywords) + White()) + clause
            parser = Forward()
            clause = Group(clause) | nestedExpr(content=parser)
            parser = operatorPrecedence(clause, [
                (Keyword('not'), 1, opAssoc.RIGHT),
                (Keyword('and'), 2, opAssoc.LEFT ),
                (Keyword('or' ), 2, opAssoc.LEFT ),])
            return parser
        # handle custom keywords (a wrapper used below)
        def _Keyword(prefix, keyword, value):
            parser = Empty()
            if prefix:
                prefix  = Optional(oneOf(prefix) + White())
                parser += Combine(prefix + Keyword(keyword))
            else:
                parser += Keyword(keyword)
            if value:
                parser += value
            return parser
        # create custom values
        name     = NotAny(oneOf('dev host'))
        name    += Word(initChars=alphas, bodyChars=alphanums+'-._')
        ip       = Combine(Word(nums, max=3) + '.' +
                           Word(nums, max=3) + '.' +
                           Word(nums, max=3) + '.' +
                           Word(nums, max=3))
        network  = Combine(ip + '/' + (ip | Word(nums, max=2)) |
                           ip + White() + 'netmask' + White() + ip)
        number   = Word(nums, max=5)
        # create custom keywords
        dev      = _Keyword('in out' , 'dev' , Boolean(name))
        host     = _Keyword('src dst', 'host', Boolean(ip | name))
        net      = _Keyword('src dst', 'net' , Boolean(network))
        port     = _Keyword('src dst', 'port', Boolean(number))
        proto    = _Keyword(None     , 'ip'  , None)
        proto   |= _Keyword(None     , 'icmp', None)
        proto   |= _Keyword(None     , 'tcp' , Optional(port))
        proto   |= _Keyword(None     , 'udp' , Optional(port))
        keyword  = dev | host | net | port | proto
        # the whole filter must be a boolean expression (possibly a single
        # keyword or value) that can begin with a reserved keyword (because
        # it's a clause that is part of a boolean expression, not a value)
        parser = Optional('any' | Boolean(keyword, True))
        return StringStart() + parser + StringEnd()
        #
    @staticmethod
    def _process_boolean(tokens, callback_func, callback_args=None):
        """Handles tokens that describe a boolean expression. We must provide
        a callback function that handles the operands (keywords or values)."""
        # convert the token list into a tuple, remember that all the arguments
        # of a cached function must be hashable! the tokens are used in such
        # functions below (see 'chech_tokens()')
        tokens = tuple(tokens)
        # shortcut for recursive calls
        recurse = lambda tokens: (
            Netfilter._process_boolean(tokens, callback_func, callback_args))
        # if we have a single list of tokens, process the elements recursively
        if check_tokens(tokens, (ParseResults,)) == 1:
            return recurse(tokens[0])
        # if we have a 'not' operator, process the operand recursively and
        # apply a negation to the result
        if check_tokens(tokens, ('not', ParseResults)) == 2:
            rules = []
            operand = recurse(tokens[1])
            # use the '!' syntax if we have a single result
            if len(operand) == 1:
                rule = operand[0]
                rules.append((rule[0], '! %s' % rule[1], rule[2]))
            # otherwise, build a dedicated netfilter chain where the original
            # target was replaced by a RETURN target
            else:
                for chain, condition, target in operand:
                    # replace the original target by a RETURN target
                    if target == operand[-1][2]:
                        target = 'RETURN'
                    rules.append((chain, condition, target))
                # add a last rule that points to the original target in case
                # no of the other rules has matched
                rules.append((operand[0][0], '', operand[-1][2]))
            return rules
        # if we have a 'and' operator, process each operand recursively and
        # connect the results by modifying chains and targets properly
        if check_tokens(tokens, (ParseResults, 'and', ParseResults)) >= 3:
            operand1 = recurse(tokens[0])
            operand2 = recurse(tokens[2:]) # the slice handles the case where
                                           # we have more than 2 operands
            rules = []
            for chain, condition, target in operand2:
                if chain == operand2[0][0]:
                    chain = operand1[-1][2]
                if target == operand2[0][0]:
                    target = operand1[-1][2]
                rules.append((chain, condition, target))
            rules = operand1 + rules
            return rules
        # if we have a 'or' operator, process each operand recursively and
        # connect the results by modifying chains and targets properly
        if check_tokens(tokens, (ParseResults, 'or', ParseResults)) >= 3:
            operand1 = recurse(tokens[0])
            operand2 = recurse(tokens[2:]) # the slice handles the case where
                                           # we have more than 2 operands
            rules = []
            for chain, condition, target in operand2:
                if chain == operand2[0][0]:
                    chain = operand1[0][0]
                elif chain == operand2[-1][2]:
                    chain = operand1[-1][2]
                if target == operand2[0][0]:
                    target = operand1[0][0]
                elif target == operand2[-1][2]:
                    target = operand1[-1][2]
                rules.append((chain, condition, target))
            rules = operand1 + rules
            return rules
        # if we have a single operand, process it with the callback function,
        # with or without arguments
        elif callback_args:
            return callback_func(tokens, callback_args)
        else:
            return callback_func(tokens)
        #
    @staticmethod
    def _process_keyword(tokens):
        """Handles tokens that describe a custom keyword ('dev', 'host', 'net',
        'port', etc)."""
        # if we have a single string, it should be a protocol, it works also if
        # we have no filter at all
        if check_tokens(tokens, (basestring,)) == 1:
            if tokens[0] in ('ip', 'any'):
                condition = '' # nothing to do
            elif tokens[0] in ('icmp', 'tcp', 'udp'):
                condition = '-p %s' % tokens[0]
            else:
                raise ParseException(trunc_repr(tokens))
            chain = Netfilter._new_chain_id()
            target = Netfilter._new_chain_id()
            return [(chain, condition, target)]
        # if we have a direction+keyword and a value
        if check_tokens(tokens, (basestring, ParseResults)) == 2:
            protocol = '' # no protocol specified here
            direction, _, keyword = tokens[0].rpartition(' ')
            value = tokens[1]
        # if we have a protocol, a direction+keyword and a value
        elif check_tokens(tokens, (basestring, basestring, ParseResults)) == 3:
            protocol = tokens[0]
            direction, _, keyword = tokens[1].rpartition(' ')
            value = tokens[2]
        # if we have no filter at all
        elif not tokens:
            chain = Netfilter._new_chain_id()
            target = Netfilter._new_chain_id()
            return [(chain, '', target)]
        else:
            raise ParseException(trunc_repr(tokens))
        # now parse the value associated with the keyword, it can be a single
        # value or a boolean expression so we use '_process_boolean()' with
        # '_process_value()' as a callback function
        callback_func = Netfilter._process_value
        callback_args = {'protocol' : protocol,
                         'direction': direction,
                         'keyword'  : keyword,}
        return Netfilter._process_boolean(value, callback_func, callback_args)
        #
    @staticmethod
    def _process_value(tokens, context):
        """Handles tokens that describe a single value (IP, network, etc)."""
        # get the context required to choose the right iptables options
        protocol = context['protocol']
        direction = context['direction']
        keyword = context['keyword']
        # select the appropriate iptables options
        options_by_direction = {'in' : 0,
                                'out': 1,
                                'src': 0,
                                'dst': 1,}
        options_by_keyword   = {'dev' : ['-i', '-o'],
                                'host': ['-s', '-d'],
                                'net' : ['-s', '-d'],
                                'port': ['--sport', '--dport'],}
        options = options_by_keyword[keyword]
        if direction:
            options = [options[options_by_direction[direction]]]
        # try to resolve hostnames
        if keyword == 'host' and not r(r'^[0-9]{1,3}\.').match(tokens[0]):
            hostname = tokens[0]
            try:
                logging_info("querying name %s..." % trunc_repr(hostname))
                values = resolver.query(hostname)
                if values:
                    logging_debug("name %s resolved:" % (trunc_repr(hostname)))
                    for value in values:
                        logging_debug("- %s" % value)
                else:
                    raise ValueError("can't resolve %s" % trunc_repr(hostname))
            except:
                raise ValueError("can't resolve %s" % trunc_repr(hostname))
        else:
            values = [tokens[0]]
        # if we have a port we need to specify for which protocol
        if keyword == 'port':
            new_options = []
            for option in options:
                if protocol in ['', 'tcp']:
                    new_options.append('-p tcp %s' % option)
                if protocol in ['', 'udp']:
                    new_options.append('-p udp %s' % option)
            options = new_options
        # use the selected options to create netfilter rules, each rule is
        # composed of a chain, a condition (iptables syntax) and a target
        rules = []
        chain = Netfilter._new_chain_id()
        target = Netfilter._new_chain_id()
        for value in values:
            for option in options:
                condition = '%s %s' % (option, value)
                rules.append((chain, condition, target))
        return rules
        #
    @staticmethod
    def _apply_rules(table, first_chain, rules, last_target):
        """Applies a set of rules in a given Netfilter table. Rules must be
        generated by '_process_*()' handlers (see above)."""
        # create new proxyshark chains
        new_chains = list(set([x[0] for x in rules] + [x[2] for x in rules]))
        Netfilter_raw_iptables = Netfilter._raw_iptables
        Netfilter_existing_chains = Netfilter._existing_chains
        Netfilter_existing_chains_append = Netfilter._existing_chains.append
        for new_chain in new_chains:
            if new_chain not in Netfilter_existing_chains:
                Netfilter_raw_iptables('-t %s -N %s' % (table, new_chain))
                Netfilter_existing_chains_append(new_chain)
        # remove doubles
        Netfilter._existing_chains = list(set(Netfilter._existing_chains))
        # now fill the chains with our rules!
        reversed_rules = list(rules) # copy the rules
        reversed_rules.reverse()
        if reversed_rules[0][-1] == 'RETURN':
            args = table, reversed_rules[0][0], last_target
            Netfilter._raw_iptables('-t %s -A %s -j %s' % args)
        else:
            args = table, reversed_rules[0][-1], last_target
            Netfilter._raw_iptables('-t %s -A %s -j %s' % args)
        for chain, condition, target in reversed_rules:
            if condition:
                condition = ' %s' % condition
            args = table, chain, condition, target
            Netfilter._raw_iptables('-t %s -A %s%s -j %s' % args)
        args = table, first_chain, reversed_rules[-1][0]
        Netfilter._raw_iptables('-t %s -I %s 1 -j %s' % args)
        # remember that '_raw_iptables()' is cached, so a rule can't be added
        # twice even if the function is called several times (once for each of
        # the 3 netfilter chains INPUT, OUTPUT and FORWARD)
        #
    @staticmethod
    @cached # can't run the same iptables command more than once!
    def _raw_iptables(args):
        """Runs iptables with the given command line arguments."""
        # don't log -D, -F, -N and -X lines
        no_stderr = ''
        for no_display_arg in ('D', 'F', 'N', 'X'):
            if r(r'-\b%s\b' % no_display_arg).search(args):
                no_stderr = ' 2> /dev/null'
                break
        else:
            logging_debug("iptables %s" % args)
        os.system('iptables %s%s' % (args, no_stderr))
        #
    #

###############################################################################
# Classes (packet filters)
###############################################################################

class PacketFilter:
    """Provides static methods to handle packet filters."""
    # Public methods ##########################################################
    @staticmethod
    def match(packet, packet_filter):
        """Checks if the given packet matches the given filter."""
        return bool(PacketFilter.evaluate(packet, packet_filter))
        #
    @staticmethod
    def evaluate(packet, packet_filter):
        """Evaluates the given packet filter and returns the result."""
        result = True
        if verbose_level > 2:
            if packet.identifier:
                logging_debug("evaluating packet filter %s on packet #%s:"
                              % (trunc_repr(packet_filter),
                                 packet.identifier))
            else:
                logging_debug("evaluating packet filter %s:"
                              % trunc_repr(packet_filter))
        packet_filter = packet_filter.strip()
        if packet_filter:
            # here we use a cached method to get the tokens, so the parser
            # won't be called each time we use 'evaluate()'
            tokens = PacketFilter._tokens_from_packet_filter(packet_filter)
            result = PacketFilter._process_boolean(tokens, packet)
        if verbose_level > 2:
            logging_debug("- result = %s" % result)
        return result
        #
    # Built-in methods ########################################################
    #
    # Private methods #########################################################
    @staticmethod
    @cached
    def _packet_filter_parser():
        """Creates a parser to handle packet filters."""
        # handle boolean expressions ('not', 'and', 'or')
        def Boolean(clause):
            parser = Forward()
            clause = Group(clause) | nestedExpr(content=parser)
            parser = operatorPrecedence(clause, [
                (Keyword('not'), 1, opAssoc.RIGHT),
                (Keyword('and'), 2, opAssoc.LEFT ),
                (Keyword('or' ), 2, opAssoc.LEFT ),])
            return parser
        # create custom values
        item_name   = Word(alphas + '-._') # either a protocol or a field name
        attr_name   = Word(alphas)
        slice_key   = Word('-' + nums + ':')
        attr_slice  = '[' + ((attr_name + ']' +
                              Optional('[' + slice_key + ']')) |
                             slice_key + ']')
        operand     = item_name + Optional(attr_slice)
        operand     = oneOf('len nb') + '(' + operand + ')' | operand
        operator    = oneOf('== = != ^= *= $= <= < >= >')
        printable   = alphanums + string.punctuation
        item_value  = quotedString(printable + ' ')
        item_value |= Word(printable, excludeChars=')')
        condition   = Combine(operand) + Optional(operator + item_value)
        parser = Optional('any' | Boolean(condition))
        return StringStart() + parser + StringEnd()
        #
    @staticmethod
    def _process_boolean(tokens, packet):
        """Handles tokens that describe a boolean expression."""
        # convert the token list into a tuple, remember that all the arguments
        # of a cached function must be hashable! the tokens are used in such
        # functions below (see 'chech_tokens()')
        tokens = tuple(tokens)
         # shortcut for recursive calls
        recurse = PacketFilter._process_boolean
        # if we have a single list of tokens, process the elements recursively
        if check_tokens(tokens, (ParseResults,)) == 1:
            return recurse(tokens[0], packet)
        # if we have a 'not' operator, process the operand recursively and
        # apply a negation to the result
        if check_tokens(tokens, ('not', ParseResults)) == 2:
            return not recurse(tokens[1], packet)
        # if we have a 'and' operator, process each operand recursively
        if check_tokens(tokens, (ParseResults, 'and', ParseResults)) >= 3:
            # the slice handles the case where we have more than 2 operands
            return recurse(tokens[0], packet) and recurse(tokens[2:], packet)
        # if we have a 'or' operator, process each operand recursively
        if check_tokens(tokens, (ParseResults, 'or', ParseResults)) >= 3:
            # the slice handles the case where we have more than 2 operands
            return recurse(tokens[0], packet) or recurse(tokens[2:], packet)
        # if we have a single operand, process it with '_process_condition()'
        return PacketFilter._process_condition(tokens, packet)
        #
    @staticmethod
    def _process_condition(tokens, packet):
        """Handles tokens that describe a condition (an item and an optional
        operator and value)."""
         # shortcut for recursive calls
        recurse = PacketFilter._process_condition
        # associate a python function to each available operator
        operators = {
            '==' : '__eq__',
            '='  : '__eq__',
            '!=' : '__ne__',
            '^=' : 'startswith',
            '*=' : '__contains__',
            '$=' : 'endswith',
            '<=' : '__le__',
            '<'  : '__lt__',
            '>=' : '__ge__',
            '>'  : '__gt__',}
        # if we have a single list of tokens, process the elements recursively
        if check_tokens(tokens, (ParseResults,)) == 1:
            return recurse(tokens[0], packet)
        # extract the elements in case we have a left-operand without operator
        if check_tokens(tokens, (basestring,)) == 1:
            left_operand, operator, value = tokens[0], None, None
        # extract the elements in case we have a left-operand with an operator
        elif check_tokens(tokens, (basestring,)) == 3:
            left_operand, operator, value = tokens
        else:
            raise ParseException(trunc_repr(tokens))
        # now extract the details from the left-operand
        findings = r(r'^(?:(len|nb)\()?'    # function name
                     r'([a-z-._]+)'         # item name
                     r'(?:\[([a-z]+)\])?'   # attribute name
                     r'(?:\[([-0-9:]+)\])?' # slice key
                     r'\)?$').findall(left_operand)
        if not findings:
            raise ParseException(trunc_repr(left_operand))
        func_name, item_name, attr_name, slice_key = findings[0]
        # retrieve the items from the packet
        if item_name == 'raw':
            item_values = [packet.data]
        elif attr_name:
            key = '%s[%s]' % (item_name, attr_name)
            item_values = packet.lookup(key)
        elif operator:
            key = '%s[show]' % item_name
            item_values = packet.lookup(key)
        else:
            key = '%s' % item_name
            item_values = packet.lookup(key)
        # apply the slices and remove O and None values from the results
        operand_values = []
        for item_value in item_values:
            if slice_key:
                item_value = eval('item_value[%s]' % slice_key)
            if bool(item_value):
                operand_values.append(item_value)
        # return either the items themselves or the result of the function
        if item_name == 'raw':
            if func_name == 'len':
                operand_values = [packet.data_length]
            elif func_name == 'nb':
                operand_values = [1]
        elif attr_name:
            if func_name == 'len':
                operand_values = [sum(map(len, operand_values))]
            elif func_name == 'nb':
                operand_values = [len(operand_values)]
        else:
            if func_name == 'len':
                item_values = packet.lookup('%s[size]' % item_name)
                if item_values:
                    operand_values = [sum(map(int, item_values))]
                else:
                    operand_values = []
            elif func_name == 'nb':
                operand_values = [len(operand_values)]
        # if there is no operator, just return the result
        if not operator:
            return operand_values
        # otherwise, check each operand
        for operand_value in operand_values:
            # don't process None values, however it can be 0!
            if operand_value is None:
                continue
            # check if the left-operand is a number
            try:
                operand_value = repr(float(operand_value))
            # check if it's an hexa number
            except:
                try:
                    operand_value = str(operand_value)
                    if operand_value.startswith('0x'):
                        operand_value = float(int(operand_value, 16))
                except ValueError:
                    pass
                # in all cases, get its representation
                operand_value = repr(operand_value)
            # jump directly here if the left-operand is a number
            finally:
                # evaluate the right-operand if it's protected between quotes
                if value.startswith('"') and value.endswith('"'):
                    value = eval(value)
                elif value.startswith('\'') and value.endswith('\''):
                    value = eval(value)
                # check if the right-operand is a number
                try:
                    value = float(value)
                # check if it's an hexa number
                except:
                    try:
                        value = str(value)
                        if value.startswith('0x'):
                            value = float(int(value, 16))
                    except ValueError:
                        pass
                # in all cases, get its representation
                value = repr(value)
                # finally, compare both values with the appropriate operator
                try:
                    function = operators[operator]
                    cmdline = ('%s.%s(%s)' % (operand_value, function, value))
                    result = eval(cmdline)
                    if result is NotImplemented:
                        result = False
                except Exception, exception:
                    logging_exception(exception)
                    result = None
                finally:
                    if verbose_level > 2:
                        logging_debug("- eval(%s) = %s" % (cmdline, result))
            # accept the packet at the first match
            if result:
                return True
        # otherwise, reject it
        return False
        #
    @staticmethod
    @cached
    def _tokens_from_packet_filter(packet_filter):
        """Generates tokens from a given packet filter (see 'evaluate()')."""
        parser = PacketFilter._packet_filter_parser()
        tokens = parser.parseString(packet_filter)
        return tokens
        #
    #

###############################################################################
# Classes (packet dissection)
###############################################################################

class DissectionException(Exception):
    pass
    #

class DissectedPacket:
    """A dissected packet as seen by Wireshark and tshark (a tree structure of
    protocols and fields)."""
    _last_real_identifier = 1
    _last_identifier = 1
    # Public methods ##########################################################
    def __init__(self, nfq_handle, nfq_data, description, xml_data,
                 etree_packet, field_filter):
        """
        Create a new dissected packet from raw data coming from the queue.

        nfq_handle   -- connection handle from the Netfilter queue
        nfq_data     -- Netlink data from the Netfilter queue
        description  -- packet descrition from tshark in text mode
        xml_data     -- raw XML data received from tshark
        etree_packet -- etree.Element instance from a PDML <packet/> tag
        field_filter -- regular expression to select protocols and fields

        """
        # initialization
        self.nfq_handle = nfq_handle
        self.nfq_data = nfq_data
        self.description = r(r' +').sub(' ', description).strip()
        self.xml_data = xml_data
        self.etree_packet = etree_packet
        self.field_filter = field_filter
        full_msg_packet_hdr = libnfq.get_full_msg_packet_hdr(nfq_data)
        self.nfq_packet_id = full_msg_packet_hdr['packet_id']
        self.indev = network_devices(libnfq.get_indev(nfq_data))
        self.outdev = network_devices(libnfq.get_outdev(nfq_data))
        self.verdict = None
        # define a dictionary of committed fields, and a dictionary of fields
        # to commit, fields are written to the packet with 'self.__setitem__()'
        # and 'self.commit()'
        self._committed_items = {}
        self._new_items = copy.deepcopy(self.read_items())
        # get raw data and packet length
        self.data_length, self.data = libnfq.get_full_payload(nfq_data)
        # get the packet identifier
        self.real_identifier = DissectedPacket._last_real_identifier
        DissectedPacket._last_real_identifier += 1
        self.identifier = None
        # retrieve the packet stream identifier
        try:
            self.stream = int(self.__getitem__('tcp.stream[show]')[0])
        except:
            self.stream = None
        # retrieve the packet attributes from its description
        regex = r'^ *(\d+\.\d+) +([^ ]+) +-> +([^ ]+) +([^ ]+) +[^ ]+ +(.*)$'
        findings = r(regex).findall(description)
        if not findings or len(findings[0]) != 5:
            raise ValueError("invalid packet description %s"
                             % trunc_repr(description))
        try:
            self.timestamp = float(findings[0][0])
            self.source = findings[0][1]
            self.destination = findings[0][2]
            self.protocol = findings[0][3]
            self.info = findings[0][4]
        except:
            raise ValueError("can't parse packet description %s"
                             % trunc_repr(description))
        #
    @cached
    def lookup(self, key):
        """Uses the given key to search items in the current packet. The key
        could be a protocol name or a field name."""
        item_name, _, attr_name = key.partition('[')
        attr_name = attr_name.rstrip(']')
        if '.' in item_name:
            xpath = 'proto//field[@name="%s"]' % item_name
            items = self.etree_packet.findall(xpath)
        else:
            xpath = 'proto[@name="%s"]' % item_name
            items = self.etree_packet.findall(xpath)
            if items:
                attr_name = r(r'\bshow\b').sub('showname', attr_name)
        if attr_name:
            result = [x.attrib.get(attr_name) for x in items]
        else:
            result = [x.attrib for x in items]
        return result
        #
    @cached
    def match(self, packet_filter):
        """Checks if the current packet matches the given filter."""
        result = PacketFilter.match(self, packet_filter)
        # set a new identifier if needed
        if result and not self.identifier:
            self.identifier = DissectedPacket._last_identifier
            DissectedPacket._last_identifier += 1
        return result
        #
    @cached
    def evaluate(self, packet_filter):
        """Evaluates the given packet filter and returns the result."""
        return PacketFilter.evaluate(self, packet_filter)
        #
    def read_items(self):
        """Returns a list of dictionaries representing all the protocols and
        fields of the current packet. Items are taken either from the XML tree
        or from the last committed items."""
        items = self._committed_items
        return items if items else self._read_items()
        #
    @cached # these items won't be updated even if we write the packet
    def _read_items(self):
        """Reads items of the current packet from the XML tree."""
        last_proto_name = None
        items = [] # [{name='...', pos='', size='', value='', show=''}, ...]
        for item in self.__iter__():
            # get item name
            item_name = item.get('name')
            # apply the field filter
            if self.field_filter:
                start = '' if '^' in self.field_filter else '.*'
                end   = '' if '$' in self.field_filter else '.*'
                regex = r'%s(%s)%s' % (start, self.field_filter, end)
                if not r(regex).match(item_name):
                    continue
            # skip hidden items
            item_hide = item.get('hide')
            if item_hide and item_hide == 'yes':
                continue
            # get item position
            item_pos = item.get('pos')
            if not item_pos:
                continue
            # get item size
            item_size = item.get('size')
            if not item_size:
                continue
            # check the item tag
            if item.tag == 'field':
                # if the name is empty, use '<proto>.data'
                if not item_name:
                    if last_proto_name:
                        item_name = '%s.data' % last_proto_name
                        item.set('name', item_name)
                    else:
                        continue
                # get field value
                item_value = item.get('value')
                if not item_value:
                    continue
                try:
                    if len(item_value) != int(item_size) * 2:
                        continue
                except:
                    continue
                # get pretty value
                item_show = item.get('show')
                if not item_show:
                    continue
                # get alternative pretty value
                item_showname = item.get('showname')
                # add a new field to the list
                if item_showname:
                    attributes = {
                        'name'    : item_name,
                        'pos'     : item_pos,
                        'size'    : item_size,
                        'value'   : urllib.quote(item_value),
                        'show'    : urllib.quote(item_show),
                        'showname': urllib.quote(item_showname),}
                else:
                    attributes = {
                        'name' : item_name,
                        'pos'  : item_pos,
                        'size' : item_size,
                        'value': urllib.quote(item_value),
                        'show' : urllib.quote(item_show),}
                items.append(attributes)
            elif item.tag == 'proto':
                # a protocol must have a name
                if not item_name:
                    continue
                # get alternative pretty value
                item_showname = item.get('showname')
                if not item_showname:
                    continue
                # add a new protocol to the list
                attributes = {
                    'name'    : item_name,
                    'pos'     : item_pos,
                    'size'    : item_size,
                    'showname': urllib.quote(item_showname),}
                items.append(attributes)
                last_proto_name = item_name
            else:
                continue
        return items
        #
    def commit(self, new_items=None):
        """Writes the given set of items. The argument must be a list of
        dictionaries representing the fields to modify. If no argument is
        given, use 'self._new_items' instead. Returns True if the packet was
        modified."""
        # retrieve old and new items
        old_items = self.read_items()
        if not new_items:
            new_items = self._new_items
        # skip if the packet wasn't modified
        if old_items == new_items:
            logging_debug("packet wasn't modified, nothing to commit")
            return False
        if len(old_items) != len(new_items):
            logging_error("items have inconsistent sizes! (%s != %s)"
                          % (len(old_items),
                             len(new_items)))
            return False
        # process each item one by one
        logging_debug("committing new items...")
        if verbose_level > 2:
            logging_print("Old items was:")
            logging_print(repr(old_items))
            logging_print("New items are:")
            logging_print(repr(new_items))
        offset = 0 # offset in case of increase/decrease of an item size
        new_data = self.data
        packet_modified = False
        for old_item, new_item in zip(old_items, new_items):
            # get item name
            item_name = new_item.get('name')
            if not item_name:
                logging_error("commit failed, no name in item %s"
                              % trunc_repr(new_item))
                return False
            if item_name != old_item.get('name'):
                logging_error("commit failed, corrupted item name! (%s != %s)"
                              % (trunc_repr(item_name),
                                 trunc_repr(old_item.get('name'))))
                return False
            # ensute that we have a field and not a protocol
            if '.' not in item_name:
                continue
            # get item position
            item_pos = new_item.get('pos')
            if not item_pos:
                logging_error("commit failed, no position in item %s"
                              % trunc_repr(item_name))
                return False
            if item_pos != old_item.get('pos'):
                logging_error("commit failed, corrupted position! (%s != %s)"
                              % (trunc_repr(item_pos),
                                 trunc_repr(old_item.get('pos'))))
                return False
            try:
                item_pos = int(item_pos)
            except:
                logging_error("commit failed, invalid position %s"
                              % trunc_repr(item_pos))
                return False
            # get item size
            item_size = new_item.get('size')
            if not item_size:
                logging_error("commit failed, no size in item %s"
                              % trunc_repr(item_name))
                return False
            if item_size != old_item.get('size'):
                logging_error("commit failed, corrupted size! (%s != %s)"
                              % (trunc_repr(item_size),
                                 trunc_repr(old_item.get('size'))))
                return False
            try:
                item_size = int(item_size)
            except:
                logging_error("commit failed, invalid size %s"
                              % trunc_repr(item_size))
                return False
            # get item value
            item_value = new_item.get('value')
            if not item_value:
                logging_error("commit failed, no value in item %s"
                              % trunc_repr(item_name))
                return False
            try:
                item_value_ascii = binascii.a2b_hex(item_value)
            except:
                logging_error("commit failed, unable to unhex value %s"
                              % trunc_repr(item_value))
                return False
            # get pretty value
            item_show = new_item.get('show')
            if not item_show:
                logging_error("commit failed, no pretty value in item %s"
                              % trunc_repr(item_name))
                return False
            if item_show != old_item.get('show'):
                logging_error("commit failed, corrupted pretty value! "
                              "(%s != %s)"
                              % (trunc_repr(item_show),
                                 trunc_repr(old_item.get('show'))))
                return False
            # get alternative pretty value (optional)
            item_showname = new_item.get('showname')
            if item_showname and item_showname != old_item.get('showname'):
                logging_error("commit failed, corrupted alt pretty value! "
                              "(%s != %s)"
                              % (trunc_repr(item_showname),
                                 trunc_repr(old_item.get('showname'))))
                return False
            # define new attribute values
            attr_pos = str(item_pos+offset)
            attr_size = str(len(item_value_ascii))
            # if the current item was modified, update its position, size,
            # value, pretty value, alternative pretty value and raw data in
            # both items and xml tree, otherwise, update only its position and
            # size to reflect the new offset
            if item_value != old_item.get('value'):
                packet_modified = True
                # define missing attribute values
                attr_value = item_value
                attr_show = '<<%s>>' % trunc_repr(item_value_ascii)[1:-1]
                attr_showname = ('<<%s: %s>>' # ex: '<<Src: 1.2.3.4>>"
                                 % (item_name.rpartition('.')[2].title(),
                                    trunc_repr(item_value_ascii)[1:-1]))
                # update the current item
                new_item['pos'] = attr_pos
                new_item['size'] = attr_size
                #new_item['value'] = attr_value # the value is already set
                new_item['show'] = attr_show
                new_item['showname'] = attr_showname
                new_item['modified'] = '1'
                # update the xml tree
                xpath = 'proto//field[@name=%s]' % repr(item_name)
                items = self.etree_packet.findall(xpath)
                for item in items:
                    item.set('pos', attr_pos)
                    item.set('size', attr_size)
                    item.set('value', attr_value)
                    item.set('show', attr_show)
                    if item_showname: # only if we have an alt pretty name
                        item.set('showname', attr_showname)
                    item.set('modified', '1')
            else:
                # update the current item
                new_item['pos'] = attr_pos
                new_item['size'] = attr_size
                # update the xml tree
                xpath = 'proto//field[@name=%s]' % repr(item_name)
                items = self.etree_packet.findall(xpath)
                for item in items:
                    item.set('pos', attr_pos)
                    item.set('size', attr_size)
            # build the new payload
            new_data = (new_data[:item_pos+offset] +
                        item_value_ascii +
                        new_data[item_pos+item_size+offset:])
            offset += len(item_value_ascii) - item_size
        # recalculate the checksums
        scapy_packet = IP(new_data)
        scapy_packet[IP].len += offset
        del scapy_packet[IP].chksum
        scapy_packet = IP(str(scapy_packet))
        if TCP in scapy_packet:
            del scapy_packet[TCP].chksum
        if UDP in scapy_packet:
            del scapy_packet[UDP].chksum
        new_data = str(scapy_packet)
        # save the new payload
        self.data = new_data
        self.data_length += offset
        if verbose_level > 2:
            logging_print("Old payload was:")
            logging_print(repr(self.data))
            logging_print("New payload is:")
            logging_print(repr(new_data))
        # save the committed items
        self._committed_items = new_items
        self._new_items = copy.deepcopy(self._committed_items)
        # return the modification state
        return packet_modified
        #
    def accept(self):
        """Accepts the packet."""
        self._set_verdict(libnfq.NF_ACCEPT)
        #
    def drop(self):
        """Drops the packet."""
        self._set_verdict(libnfq.NF_DROP)
        #
    # Built-in methods ########################################################
    def __getitem__(self, packet_filter):
        """Evaluates the given packet filter and returns the result."""
        return PacketFilter.evaluate(self, packet_filter)
        #
    def __setitem__(self, field_name, new_value):
        """Puts a new value in the field given in argument. The new value must
        be a raw string without ASCII-HEX representation."""
        # ensure that we have a field name (without space or bracket)
        field_name = field_name.strip()
        if ' ' in field_name or field_name.endswith(']'):
            raise KeyError("argument %s must be a valid field name!"
                           % trunc_repr(field_name))
        # search items with the right name
        modified = False
        for item in self._new_items:
            # get item name
            item_name = item.get('name')
            if not item_name:
                continue
            # ensure that we have a field name
            if '.' not in item_name:
                continue
            # if the name matches, set the value
            if item_name == field_name:
                modified = True
                item['value'] = binascii.b2a_hex(new_value)
        if not modified:
            KeyError("field %s was not found!" % trunc_repr(field_name))
        #
    def __iter__(self):
        """Returns an iterator on the packet items."""
        return self.etree_packet.iter()
        #
    def __str__(self):
        """Returns the packet description and items."""
        # commit pending items to reflect any possible modifications
        self.commit()
        # get items and max length for each attribute
        items = self.read_items()
        max_length = {
            'name'    : 0,
            'value'   : 0,
            'show'    : 0,
            'showname': 0,}
        for item in items:
            item_name = item.get('name')
            if item_name:
                length = len(item_name)
                if length > max_length['name']:
                    max_length['name'] = length
            item_value = item.get('value')
            if item_value:
                length = len(truncated(urllib.unquote(item_value), 32))
                if length > max_length['value']:
                    max_length['value'] = length
            item_show = item.get('show')
            if item_show:
                length = len(truncated(urllib.unquote(item_show), 64))
                if length > max_length['show']:
                    max_length['show'] = length
            item_showname = item.get('showname')
            if '.' not in item_name and item_showname:
                length = 4
                length += len(item_name)
                length += len(urllib.unquote(item['showname']))
                if length > max_length['showname']:
                    max_length['showname'] = length
        # length of the protocol separator composed of '=' and '-'
        separator_length = 24
        separator_length += max_length['name']
        separator_length += max_length['value']
        separator_length += max_length['show']
        separator_length = max(separator_length, max_length['showname'])
        # build the result string
        result = self.__repr__()
        for item in items:
            if 'show' in item:
                # is it a field?
                pos = int(item['pos'])
                size = int(item['size'])
                name = item['name']
                show = truncated(urllib.unquote(item['show']), 64)
                value = truncated(urllib.unquote(item['value']), 32)
                fmt = ("\n    |   %s%%-12s %%-%ss : %%-%ss (%%s)\033[0m"
                       % ("\033[1;33m" if 'modified' in item else "",
                          max_length['name'],
                          max_length['show']))
                result += (fmt
                           % ("[%s:%s]" % (pos, pos+size),
                              name,
                              show,
                              value))
            else:
                # is it a protocol?
                name = item['name']
                showname = urllib.unquote(item['showname'])
                result += "\n    " + "=" * separator_length
                result += "\n   + %s: %s" % (name, showname)
                result += "\n   \\" + "-" * separator_length
        result += "\n====" + "=" * separator_length
        return result
        #
    def __repr__(self):
        """Returns the packet description."""
        global real_verbose_level
        result = "Packet #%s/%s" % (self.identifier, self.real_identifier)
        if self.stream is not None:
            result += " (stream %s)" % self.stream
        result += ", %s" % self.description
        return result
        #
    # Private methods #########################################################
    def _set_verdict(self, verdict):
        """Sets the verdict (NF_ACCEPT or NF_DROP)."""
        if self.verdict:
            raise IOError("verdict is already set for packet #%s"
                          % self.identifier)
        libnfq.set_pyverdict(self.nfq_handle,
                             self.nfq_packet_id,
                             verdict,
                             self.data_length,
                             self.data)
        self.verdict = verdict
        #
    #

class DissectedPacketList(list):
    """A list of dissected packet."""
    # Public methods ##########################################################
    def __init__(self, *args):
        """Create a new instance."""
        super(DissectedPacketList, self).__init__(*args)
        # packet identifiers start at index 1 so we have to append a dummy
        # element in position 0
        self.append(NotImplemented)
        #
    # Built-in methods ########################################################
    def __iter__(self):
        """Implements a custom iterator that skips the first element."""
        iteraror = super(DissectedPacketList, self).__iter__()
        # don't return the first element (NotImplemented)
        iteraror.next()
        return iteraror
        #
    def __getslice__(self, i, j):
        """Implemented for compatibiliy."""
        return self.__getitem__(slice(i, j, None))
        #
    def __getitem__(self, key):
        """Evaluates 'self[key]'. The key can be a slice or a packet filter."""
        # if the key is a slice
        if isinstance(key, slice):
            # skip the first element (NotImplemented)
            if key.step is None:
                key = slice(key.start, key.stop, 1)
            if key.step >= 0:
                if not key.start:
                    key = slice(1, key.stop, key.step)
            else:
                if not key.stop:
                    key = slice(key.start, 0, key.step)
            # return a new packet list
            result = DissectedPacketList()
            result.extend(super(DissectedPacketList, self).__getitem__(key))
            return result
        # if the key is a packet filter
        elif isinstance(key, basestring):
            # evaluate the filter for each packet of the current list
            result = DissectedPacketSubList()
            for packet in self.__iter__():
                # if the evaluation matches, store the packet
                results = packet.evaluate(key)
                if bool(results):
                    result.append(packet)
            # return a sublist containing the packets that match
            return result
        # 
        else:
            return super(DissectedPacketList, self).__getitem__(key)
        #
    def __str__(self):
        """Prints the packet list as a well-formatted string."""
        return "\n".join([str(x) for x in self[1:]])
        #
    def __repr__(self):
        """Prints the packet list as a well-formatted string."""
        return "\n".join([repr(x) for x in self[1:]])
        #
    # Private methods #########################################################
    #

class DissectedPacketSubList(DissectedPacketList):
    """A sublist of dissected packets. The only difference with the above
    dissected list is that '__getitem__()' returns the item values and not only
    a boolean."""
    # Public methods ##########################################################
    #
    # Built-in methods ########################################################
    def __getitem__(self, key):
        """Evaluates 'self[key]'. The key can be only a packet filter. In fact,
        only a field name. Otherwise, the default method is used."""
        # ensure that we have a packet filter
        if isinstance(key, basestring):
            # ensure that we have a field name (without space)
            key = key.strip()
            if ' ' in key:
                raise KeyError("key %s must be a valid field name!"
                               % trunc_repr(key))
            # evaluate the filter for each packet
            result = {}
            for packet in self.__iter__():
                results = packet.evaluate(key)
                # make sure that we have a list as result, for consistency
                if not isinstance(results, list):
                    results = [results]
                result[packet.identifier] = results
            # return the list of results
            return result
        # otherwise, use the default method
        else:
            return super(DissectedPacketSubList, self).__getitem__(key)
        #
    # Private methods #########################################################
    #

class Dissector:
    """A packet dissector based on tshark."""
    # Public methods ##########################################################
    def __init__(self, tshark_dir, quiet):
        """
        Runs 2 instances of tshark: one in text mode (-T text) to get general
        packet descriptions and one in PDML mode (-T pdml) to get detailed XML
        dissections.

        tshark_dir -- location of the tshark binary
        quiet      -- if True, don't print any information about the dissector
                      state

        """
        # initialization
        self.tshark_dir = tshark_dir
        self.quiet = quiet
        self._stopping = Event()
        # get the full path of tshark
        tshark_path = os.path.join(os.getcwd(), tshark_dir, 'tshark')
        if not os.path.isfile(tshark_path):
            tshark_path = 'tshark'
        # provide tshark with a global pcap header
        pcap_global_header = (
            '\xd4\xc3\xb2\xa1'  # magic number
            '\x02\x00'          # major version
            '\x04\x00'          # minor version
            '\x00\x00\x00\x00'  # gmt-to-local correction
            '\x00\x00\x00\x00'  # accuracy of timestamps
            '\xff\xff\x00\x00'  # snaplen
            '\x65\x00\x00\x00') # data link type
        # define tshark settings
        settings = ' '.join(['-o %s:%s' % (k, str(v).upper()) for k, v in [
            ('tcp.analyze_sequence_numbers' , True ),
            ('tcp.calculate_timestamps'     , True ),
            ('tcp.check_checksum'           , True ),
            ('tcp.desegment_tcp_streams'    , False),
            ('tcp.relative_sequence_numbers', True ),
            ('tcp.summary_in_tree'          , True ),
            ('tcp.track_bytes_in_flight'    , True ),
            ('tcp.try_heuristic_first'      , True ),
            ('udp.check_checksum'           , True ),
            ('udp.process_info'             , True ),
            ('udp.summary_in_tree'          , True ),
            ('udp.try_heuristic_first'      , True ),
        ]])
        # run tshark instances
        self._tshark = {}
        for mode in ('text', 'pdml'):
            cmdline = ('%s -i - -s0 -n -l -T %s %s'
                       % (tshark_path,
                          mode,
                          settings))
            self._tshark[mode] = Popen(cmdline.split(' '),
                                       preexec_fn=os.setpgrp, # don't forward
                                                              # signals
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
        if not self.quiet:
            logging_info("dissector started")
        #
    def dissect(self, nfq_handle, nfq_data, field_filter):
        """
        Returns a tuple composed of a short description and an etree.Element
        describing the packet given in argument.

        nfq_handle   -- connection handle from the Netfilter queue
        nfq_data     -- Netlink packet data from the Netfilter queue
        field_filter -- regular expression used to select protocols and fields

        """
        try:
            # get raw data and packet length
            data_length, data = libnfq.get_full_payload(nfq_data)
            # get the current timestamp
            current_time = time.time()
            sec = int(current_time)
            usec = int((current_time - sec) * 1000000)
            # create a valid pcap header
            packed_data_length = struct.pack('I', data_length)
            pcap_data = ''.join((struct.pack('I', sec),
                                 struct.pack('I', usec),
                                 packed_data_length,
                                 packed_data_length,
                                 data))
            # send the packet to tshark
            for mode in ('text', 'pdml'):
                self._tshark[mode].stdin.write(pcap_data)
                self._tshark[mode].stdin.flush()
            # retrieve packet description and xml dissection
            parser = XMLParser()
            description = self._tshark['text'].stdout.readline().rstrip('\n')
            readline = self._tshark['pdml'].stdout.readline
            xml_lines = []
            xml_lines_append = xml_lines.append
            parser_feed = xml_lines_append
            # wait for a packet start
            while 1:
                line = readline()
                if line is None:
                    raise DissectionException("unexpected end of file!")
                if line == '<packet>\n':
                    break
            # wait for the ip layer
            while 1:
                line = readline()
                if line is None:
                    raise DissectionException("unexpected end of file!")
                if '<proto name="ip"' in line:
                    parser_feed('<packet>\n')
                    parser_feed(line)
                    break
            # wait for the packet end
            while 1:
                line = readline()
                if line is None:
                    raise DissectionException("unexpected end of file!")
                parser_feed(line)
                if line == '</packet>\n':
                    xml_data = ''.join(xml_lines)
                    parser.feed(xml_data)
                    break
            # create a new dissected packet
            return DissectedPacket(nfq_handle,
                                   nfq_data,
                                   description,
                                   xml_data,
                                   parser.close(),
                                   field_filter)
        except IOError:
            return None
        #
    def stop(self):
        """Stops tshark instances properly."""
        if self._stopping.isSet():
            return
        self._stopping.set()
        for mode in ('text', 'pdml'):
            tshark = self._tshark[mode]
            for send_signal in (tshark.terminate, tshark.kill):
                tshark.poll()
                if tshark.returncode >= 0:
                    break
                try:
                    send_signal()
                except OSError:
                    break
                else:
                    time.sleep(0.5)
        if not self.quiet:
            logging_info("dissector stopped")
        #
    # Built-in methods ########################################################
    #
    # Private methods #########################################################
    #

###############################################################################
# Classes (nfqueue)
###############################################################################

class NFQueue(Thread):
    """A Netfilter queue to receive packets, dissect them and make them
    available to the user."""
    # Public methods ##########################################################
    def __init__(self, tshark_dir, queue_num, proxy_ip, proxy_port, server_ip,
                 server_port, capture_filter, packet_filter, field_filter):
        """
        Creates a new Netfilter queue.

        tshark_dir     -- location of the tshark binary
        queue_num      -- number of the Netfilter queue to use
        proxy_ip       -- IP address of the web proxy to use
        proxy_port     -- port number of the web proxy to use
        server_ip      -- IP address of the web server to use
        server_port    -- port number of the web server to use
        capture_filter -- bpf-filter describing the packets to capture
        packet_filter  -- filter describing the packets to process
        field_filter   -- filter describing the fields to process

        """
        # initialization
        Thread.__init__(self, name='NFQueueThread')
        self.tshark_dir = tshark_dir
        self.queue_num = queue_num
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.capture_filter = capture_filter
        self.packet_filter = packet_filter
        self.field_filter = field_filter
        self.packets = DissectedPacketList()
        self.streams = {}
        self._stopping = Event()
        self._dissector_stopping = Event()
        self._dissector = Dissector(tshark_dir, False)
        # apply the capture filter
        Netfilter.remove_rules()
        Netfilter.apply_capture_filter(capture_filter, queue_num)
        # nfqueue settings
        self._snaplen = 65535
        self._sock_family = socket.AF_INET
        self._sock_type = 0
        # create the queue itself
        self._nfq_handle = libnfq.open_queue()
        libnfq.unbind_pf(self._nfq_handle, self._sock_family)
        libnfq.bind_pf(self._nfq_handle, self._sock_family)
        self._c_handler = libnfq.HANDLER(self._callback)
        self._nfq_connection_handle = {}
        self._nfq_connection_handle['queue'] = libnfq.create_queue(
            self._nfq_handle,
            queue_num,
            self._c_handler,
            None)
        libnfq.set_mode(self._nfq_connection_handle['queue'],
                        libnfq.NFQNL_COPY_PACKET,
                        self._snaplen)
        #
    def run(self):
        """Waits for packets from Netfilter."""
        # create a socket to receive packets
        s = socket.fromfd(libnfq.nfq_fd(libnfq.nfnlh(self._nfq_handle)),
                          self._sock_family,
                          self._sock_type)
        s.settimeout(0.1)
        logging_info("nfqueue started")
        while not self._stopping.isSet():
            try:
                data = s.recv(self._snaplen)
            except:
                continue
            else:
                libnfq.handle_packet(self._nfq_handle, data, len(data))
        # if we go there then the queue is stopping, destroy it properly
        libnfq.destroy_queue(self._nfq_connection_handle['queue'])
        libnfq.close_queue(self._nfq_handle)
        self._dissector_stopping.set()
        logging_info("nfqueue stopped")
        #
    def stop(self):
        """Stops the queue properly."""
        Netfilter.remove_rules()
        self._stopping.set()
        if not self._dissector_stopping.wait(5):
            if real_verbose_level > 0:
                logging_print("Waiting for nfqueue to stop...")
            self._dissector_stopping.wait()
        self._dissector.stop()
        #
    # Built-in methods ########################################################
    #
    # Private methods #########################################################
    def _callback(self, dummy1, dummy2, nfq_data, dummy3):
        """Handles the packets received from Netfilter."""
        try:
            # dissect the packet
            packet = self._dissector.dissect(
                self._nfq_connection_handle['queue'],
                nfq_data,
                self.field_filter)
            if not packet:
                return
            # apply the packet filter
            if not packet.match(self.packet_filter):
                packet.accept()
                return
            # store the packet in cache
            logging_info("nfqueue received packet #%s" % packet.identifier)
            self.packets.append(packet)
            # print the packet if needed
            if verbose_level > 1:
                logging_print(packet)
            elif verbose_level > 0:
                logging_print(repr(packet))
            # build a list of items
            items = packet.read_items()
            if not items:
                packet.accept()
                return
            # prepare the http headers
            post_headers = {
                'Host'            : ('%s:%s'
                                     % (self.server_ip,
                                        self.server_port)),
                'User-Agent'      : ('Proxyshark (Python/%s)'
                                     % sys.version.partition(' ')[0]),
                'Accept-Encoding' : 'identity',}
            # send a post to the local web server through the proxy
            connection = httplib.HTTPConnection(self.proxy_ip,
                                                self.proxy_port,
                                                False,
                                                1)
            connection.request('POST',
                               '/edit-packet/%s' % packet.identifier,
                               r(r' +').sub('', repr(items)),
                               post_headers)
            # send the packet, but ignore the response
            try:
                response = connection.getresponse()
            except:
                pass
        # accept the packet in case of error
        except Exception, exception:            
            logging_exception(exception)
            full_msg_packet_hdr = libnfq.get_full_msg_packet_hdr(nfq_data)
            nfq_packet_id = full_msg_packet_hdr['packet_id']
            data_length, data = libnfq.get_full_payload(nfq_data)
            libnfq.set_pyverdict(self._nfq_connection_handle['queue'],
                                 nfq_packet_id,
                                 libnfq.NF_ACCEPT,
                                 data_length,
                                 data)
        # flush the buffers
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
        #
    #

###############################################################################
# Classes (local web server)
###############################################################################

class ThreadingWebServer(ThreadingMixIn, HTTPServer):
    """A web server with multi-threading support for incoming connections."""
    pass
    #

class WebServer(Thread):
    """A local web server that receives POST requests from proxyshark."""
    # Public methods ##########################################################
    def __init__(self, server_ip, server_port):
        """Creates a new instance."""
        # initialization
        Thread.__init__(self, name='WebServerThread')
        self.server_ip = server_ip
        self.server_port = server_port
        self._server = None
        #
    def run(self):
        """Starts the web server."""
        try:
            self._server = ThreadingWebServer(
                (self.server_ip, self.server_port),
                WebRequestHandler)
            logging_info("local server listening on %s:%s"
                         % (self.server_ip,
                            self.server_port))
            self._server.serve_forever()
            self._server.socket.close()
        except Exception, exception:
            logging_exception(exception)
        finally:
            logging_info("server stopped")
        #
    def stop(self):
        """Stops the web server properly."""
        try:
            if self._server:
                self._server.shutdown()
        except AttributeError:
            pass
        #
    # Built-in methods ########################################################
    #
    # Private methods #########################################################
    #

class WebRequestHandler(BaseHTTPRequestHandler):
    """Handles incoming HTTP requests from the web server."""
    # store the last log line to avoid flooding the standard output
    _last_log = {'line': '', 'nb': 0}
    # Public methods ##########################################################
    def address_string(self):
        """Bypasses default address resolution to avoid unwanted delays."""
        return self.client_address[:2][0]
        #
    def log_request(self, code=None, size=None):
        """Logs the current request."""
        # only in verbose mode
        if verbose_level < 3:
            return
        # at this point we should have request parameters
        if not hasattr(self, 'params'):
            self.params = {}
        # build a new log line
        log_line = ("%s %s %s {...} %s"
                    % (self.client_address[0],
                       self.method,
                       self.path,
                       code))
        # get the last log line
        last_log = WebRequestHandler._last_log
        # is it again the same line?
        if cleanup_log_line(log_line) == cleanup_log_line(last_log['line']):
            last_log['nb'] += 1
        # it not, print the new line
        else:
            if last_log['nb'] > 0:
                logging_info("[repeat x%s]" % last_log['nb'])
            logging_info(log_line)
            last_log['line'] = log_line
            last_log['nb'] = 0
        # store the last log line
        WebRequestHandler._last_log = last_log
        #
    def send_not_found(self):
        """Sends an HTTP 404 NOT FOUND."""
        self.send_response(404, 'NOT FOUND')
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        #
    def do_GET(self):
        """Handles HTTP GET requests."""
        self.method = 'GET'
        self.send_not_found()
        #
    def do_POST(self):
        """Handles HTTP POST requests."""
        self.method = 'POST'
        self.handler_request()
        #
    def handler_request(self):
        """Generic request handler."""
        # set the name of the current thread
        currentThread().name = 'WebRequestHandlerThread'
        # get the path and parameters from the request
        findings = r(r'^/+([^?]*)(\?.*)?$').findall(self.path)
        if not findings:
            self.send_not_found()
            return
        # check the path
        self.path = os.path.normpath(findings[0][0])
        current_dir = os.path.realpath(os.getcwd())
        if not os.path.realpath(self.path).startswith(current_dir):
            self.send_not_found()
            return
        if self.path == '.':
            if self.method == 'GET':
                self.path = 'index.html'
            else:
                self.path = ''
        self.path = '/%s' % self.path
        # retrieve the post parameters
        if ('Content-Length' not in self.headers or
            not self.headers['Content-Length'].isdigit()
        ):
            self.send_not_found()
            return
        length = int(self.headers['Content-Length'])
        params = self.rfile.read(length)
        self.params = {}
        for param in params.split('&'):
            name, _, value = param.partition('=')
            self.params[name] = value
        # call the appropriate handler
        if self.path.startswith('/edit-packet/'):
            self.edit_packet()
        else:
            self.send_not_found()
        #
    def edit_packet(self):
        """Edit a given packet with the received parameters."""
        # retrieve the packet identifier within the path
        findings = r(r'([0-9]+)$').findall(self.path)
        if not findings:
            self.send_not_found()
            return
        try:
            identifier = int(findings[0])
            logging_info("local server received packet #%s" % identifier)
        except:
            logging_error("%s is not a valid identifier!"
                          % trunc_repr(identifier))
            self.send_not_found()
            return
        if identifier >= len(nfqueue.packets):
            logging_error("packet #%s was not found!" % identifier)
            self.send_not_found()
            return
        # retrieve the packet from cache
        packet = nfqueue.packets[identifier]
        # write the packet if needed
        modified = packet.commit(eval(self.params.keys()[0]))
        # print the packet if needed
        if modified:
            logging_info("packet #%s was modified" % packet.identifier)
            if verbose_level > 1:
                logging_print(packet)
            elif verbose_level > 0:
                logging_print(repr(packet))
        # accept the packet
        packet.accept()
        self.send_response(200, 'OK')
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        #
    # Built-in methods ########################################################
    #
    # Private methods #########################################################
    #

###############################################################################
# Classes (interactive console)
###############################################################################

class Console(InteractiveConsole):
    """ TODO """
    def __init__(self, nfqueue):
        """ TODO """
        InteractiveConsole.__init__(self, locals={
            'nfqueue': nfqueue,
            'exit'   : nfqueue.stop,
            'q'      : nfqueue.packets,
            'queue'  : nfqueue.packets,})
        self._nfqueue = nfqueue
        #
    def raw_input(self, prompt=""):
        """Overwrites the default prompt."""

        """prompt = "\r\033[1;34m>>>\033[0m "
        stream = sys.stderr
        input = sys.stdin
        prompt = str(prompt)
        if prompt:
            stream.write(prompt)
            stream.flush()
        line = input.readline()
        if not line:
            raise EOFError
        if line[-1] == '\n':
            line = line[:-1]
        return line"""

        return raw_input("\r\033[1;34m>>>\033[0m ")
        #
    def runsource(self, source, filename):
        """Interprets the command line."""
        InteractiveConsole.runsource(self, source, filename)
        """# sanitize the command line
        source = re.sub(" +", " ", source).strip()
        if source == "":
            return
        # split the command line
        source_split = source.split(" ")
        # look for the right command
        for cmd in Command.available:
            for name in cmd:
                # try to extract the command name
                result = re.search("^ *%s( |$)" % name, source.strip())
                if result is None:
                    continue
                # try to run the command
                try:
                    eval(
                        "%s(%s)" % (
                            source_split[0],
                            ", ".join([repr(arg) for arg in source_split[1:]])
                        ),
                        {source_split[0]: eval("Command.%s" % cmd[0])}
                    )
                except Exception, exception:
                    sys.stdout.write(
                        "%s\n" % exception.message
                    )
                return
        else:
            sys.stdout.write("%s: command not found\n" % source_split[0])
        """
        #
    #

###############################################################################
# Main entry point
###############################################################################

def print_usage():
    usage = """%s

    Usage: %s [arguments] with optional arguments within:

        -h : print this help and quit

        -v : verbose mode, can be specified several times for debug mode

        -q : queue number (default is 1234)

        -t : location of the tshark binary (default in $PATH or in ./bin/%s/)

        -w : web proxy and server to use in web-driven mode 
             (default is 127.0.0.1:8080:127.0.0.1:1234)

        <capture-filter> : bpf-filter describing the packets to capture

        <packet-filter>  : filter describing the packets to process

        <field-filter>   : filter describing the fields to process

    """ % (__banner__, __file__, os.uname()[4])
    logging_print(r(r'\n    ').sub('\n', usage))
    #

if __name__ == '__main__':
    # search a directory containing a tshark binary
    locations = ['bin/%s/' % os.uname()[4]]
    locations += os.environ.get('PATH').split(os.pathsep)
    for location in locations:
        candidate = os.path.join(location, 'tshark')
        if os.path.isfile(candidate):
            arg_tshark_dir = os.path.dirname(candidate)
            break
    else:
        raise RuntimeError("tshark was not found!") 
    # other default values
    arg_queue_num      = 1234
    arg_proxy_ip       = '127.0.0.1'
    arg_proxy_port     = 8080
    arg_server_ip      = '127.0.0.1'
    arg_server_port    = 1234
    arg_capture_filter = ''
    arg_packet_filter  = ''
    arg_field_filter   = ''
    # configure the logging system
    verbose_level = sys.argv.count('-v')
    logging_level = {
        0: logging.ERROR,
        1: logging.INFO,
        2: logging.DEBUG,
    }.get(verbose_level, logging.DEBUG)
    real_verbose_level = verbose_level
    logging_fmt = ("%%(asctime)s %s "
                   "Proxyshark(%%(process)s): "
                   "%%(threadName)s: "
                   "$COLOR[%%(levelname)s] %%(message)s$RESET"
                   % socket.gethostname())
    logger = logging.getLogger()
    logger.setLevel(logging_level)
    handler = logging.StreamHandler()
    handler.setFormatter(ColorFormatter(logging_fmt))
    logger.addHandler(handler)
    handler = logging.FileHandler('./proxyshark.log')
    handler.setFormatter(ColorFormatter(logging_fmt))
    logger.addHandler(handler)
    # check if we have root permissions
    if os.getuid() != 0:
        logging_error("permission denied")
        sys.exit(1)
    # parse the command line arguments
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hvq:t:w:')
    except getopt.GetoptError:
        print_usage()
        sys.exit(1)
    for opt, arg in opts:
        # -h
        if opt == '-h':
            print_usage()
            sys.exit(0)
        # -v
        elif opt == '-v':
            pass
        # -q <queue-num>
        elif opt == '-q':
            if arg.isdigit() and int(arg) >= 0 and int(arg) <= 65535:
                arg_queue_num = int(arg)
            else:
                logging_error("invalid queue number %s" % trunc_repr(arg))
                sys.exit(1)
        # -t <tshark-dir>
        elif opt == '-t':
            tshark_path = os.path.join(arg, 'tshark')
            if os.path.isfile(tshark_path):
                arg_tshark_dir = arg
            elif not os.path.isdir(arg):
                logging_error("directory %s does not exist!"
                              % trunc_repr(tshark_path))
                sys.exit(1)
            else:
                logging_error("directory %s does not contain a tshark binary!"
                              % trunc_repr(arg))
                sys.exit(1)
        # -w <proxy-ip>:<proxy-port>:<server-ip>:<server-port>
        elif opt == '-w':
            split = arg.split(':')
            if len(split) == 4:
                # proxy ip
                try:
                    socket.inet_aton(split[0])
                    arg_proxy_ip = split[0]
                except socket.error:
                    logging_error("invalid proxy ip")
                    sys.exit(1)
                # proxy port
                if (split[1].isdigit() and
                    int(split[1]) > 0 and int(split[1]) <= 65535
                ):
                    arg_proxy_port = int(split[1])
                else:
                    logging_error("invalid proxy port")
                    sys.exit(1)
                # server ip
                try:
                    socket.inet_aton(split[2])
                    arg_server_ip = split[2]
                except:
                    logging_error("invalid server ip")
                    sys.exit(1)
                # server port
                if (split[3].isdigit() and
                    int(split[3]) > 0 and int(split[3]) <= 65535
                ):
                    arg_server_port = int(split[3])
                else:
                    logging_error("invalid server port")
                    sys.exit(1)
            else:
                logging_error("invalid proxy and server specification")
                sys.exit(1)
        else:
            logging_error("unknown argument %s" % trunc_repr(opt))
            print_usage()
            sys.exit(1)
    # other arguments
    if len(args) > 0:
        arg_capture_filter = args[0]
        if len(args) > 1:
            arg_packet_filter = args[1]
            if len(args) > 2:
                arg_field_filter = args[2]
    # are we in quiet mode?
    if verbose_level == 0:
        logging_print("Running in quiet mode (use -h for help)...")
    # print current settings
    logging_info("current settings:")
    logging_info("- verbose level  = %s" % verbose_level)
    logging_info("- tshark folder  = %s" % trunc_repr(arg_tshark_dir))
    logging_info("- queue number   = %s" % arg_queue_num)
    logging_info("- web proxy      = %s:%s" % (arg_proxy_ip, arg_proxy_port))
    logging_info("- web server     = %s:%s" % (arg_server_ip, arg_server_port))
    logging_info("- capture filter = %s" % trunc_repr(arg_capture_filter))
    logging_info("- packet filter  = %s" % trunc_repr(arg_packet_filter))
    logging_info("- field filter   = %s" % trunc_repr(arg_field_filter))
    # start the netfilter queue
    try:
        nfqueue = NFQueue(arg_tshark_dir, arg_queue_num, arg_proxy_ip,
                          arg_proxy_port, arg_server_ip, arg_server_port,
                          arg_capture_filter, arg_packet_filter,
                          arg_field_filter)
        nfqueue.start()
    except Exception, exception:
        logging_exception(exception)
        sys.exit(1)
    # run the local web server
    try:
        web_server = WebServer(arg_server_ip, arg_server_port)
        web_server.start()
    except Exception, exception:
        logging_exception(exception)
        nfqueue.stop()
        sys.exit(1)
    else:
        try:
            # provide a function to jump in interactive mode
            console = Console(nfqueue)
            def interactive_mode(banner="\r"):
                logging_disable()
                time.sleep(0.5)
                mode = "<interactive mode - press Ctrl-D to jump in view mode>"
                text = "\033[0;34m%s\n\033[37m%s\033[0m"% (banner, mode)
                console.interact(text)
                save_history()
                logging_enable()
                #
            # initialize the interactive console
            load_history()
            readline.set_history_length(10*5)
            readline.parse_and_bind('"\vdraw": redraw-current-line')
            readline.parse_and_bind('"\vauto": complete')
            readline.parse_and_bind('"\veofl": end-of-line')
            readline.parse_and_bind('TAB: "\veofl\vdraw\vauto\vauto"')
            readline.parse_and_bind('RET: "\veofl\vdraw\n"')
            readline.parse_and_bind('DEL: "\b\vdraw"')
            readline.parse_and_bind('"\vback": backward-char')
            readline.parse_and_bind('"\vforw": forward-char')
            readline.parse_and_bind('"\vprev": previous-history')
            readline.parse_and_bind('"\vnext": next-history')
            readline.parse_and_bind('"\C-[[D": "\vback\vdraw"')
            readline.parse_and_bind('"\C-[[C": "\vforw\vdraw"')
            readline.parse_and_bind('"\C-[[A": "\vprev\vdraw"')
            readline.parse_and_bind('"\C-[[B": "\vnext\vdraw"')
            # initialize auto completion
            default_completer = readline.get_completer()
            def completer(text, index):
                print 1, text, index
                # exclude completion if the text is too short, and avoid
                # printing hundreads of proposals when we end Ctrl-R with TAB
                if len(text) in (0, 1):
                    return None
                # return the result but exclude private members and members
                # which contain uppercase characters
                result = default_completer(text, index)
                text_length = len(text)
                private_member = result[text_length-1:text_length+1] == '._'
                uppercase_char = r(r'[A-Z]').search(result)
                if private_member or uppercase_char:
                    result = completer(text, index+1)
                print 2, result
                return result
                #
            readline.set_completer(completer)
            # start within the console
            interactive_mode(__banner__)
            # enter the main loop
            mode = "<view mode - press Ctrl-C to jump in interactive mode>"
            while nfqueue.isAlive():
                try:
                    logging_print(mode)
                    # restore signal handling
                    signal.signal(signal.SIGINT, handler_sigint)
                    while nfqueue.isAlive():
                        if not web_server.isAlive():
                            break
                        time.sleep(0.5)
                # come back to the console in case of user interrupt
                except KeyboardInterrupt:
                    # disable signal handling
                    signal.signal(signal.SIGINT, signal.SIG_IGN)
                    interactive_mode()
            time.sleep(0.5)
        except Exception, exception:
            logging_exception(exception)
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except KeyboardInterrupt:
            pass
        # stop the threads
        web_server.stop()
        nfqueue.stop()
    logging_info("done.")
    logging.shutdown()
    # kill the main process
    os.kill(os.getuid(), signal.SIGINT)
    time.sleep(1)
    os.kill(os.getuid(), signal.SIGKILL)
    sys.exit(0)
    #

