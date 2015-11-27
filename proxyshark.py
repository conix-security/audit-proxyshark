#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# This file is part of Proxyshark, a tool designed to dissect and alter IP
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

#TODO: generate statistics about captured packets
#TODO: print status after each command
#TODO: implement .where(), .select(), .group(), .sort(), max(), min(), ...
#TODO: Breakpoint -> Handle modified packet (nfqueue verdict)
__version__ = 'Proxyshark 1.0b'

# ignore signals to let all the stuff load properly without user interrupt, we
# will re-enable signal handling later to intercept ctrl-c (sigint)
import signal
handler_sigint = signal.getsignal(signal.SIGINT)
signal.signal(signal.SIGINT, signal.SIG_IGN)

# imports

import binascii
import copy
import cProfile
import getopt
import httplib
import psnfqueue as nfqueue
import asyncore #asynchronous socket programming
import select
import logging
import os
import pprint # debug
import pstats # debug
import random
import re
import readline
import rlcompleter
import socket
import string
import struct
import sys
import time
import traceback
import urllib
from string import Template

#safer (and limited) version of eval
from ast import literal_eval

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from code import InteractiveConsole
try:
    from dns import resolver # need python-dnspython
    resolver = resolver.Resolver()
    resolver.lifetime = 3
except ImportError:
    resolver = None
from functools import wraps

# need python-pyparsing
from pyparsing import (alphas, alphanums, Combine, Empty, Forward, Group,
                       Keyword, nestedExpr, NotAny, nums, oneOf, opAssoc,
                       operatorPrecedence, Optional, OneOrMore, ParseException,
                       ParseBaseException, ParseResults, quotedString,
                       StringEnd, StringStart, Suppress, White, Word)
alphanums += '-._'
from SocketServer import ThreadingMixIn
from subprocess import Popen, PIPE
from threading import currentThread, Event, RLock, Lock, Thread

from xml.etree.cElementTree import XMLParser

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import conf as scapy_conf, L3RawSocket, IP, TCP, UDP, send
                      # need python-scapy

# global variables shared between all threads
shared = { 'logging': False,  # will be enabled below
           'logger' : None,   # defined below
           'stats'  : None, } # defined below

# default settings
settings = { 'real_verbose_level'     : 0,
             'effective_verbose_level': 0,
             'ethernet_layer'         : False,
             'queue_number'           : 1234,
             'tshark_directory'       : None, # defined below
             'web_driven'             : False,
             'web_server_host'        : '127.0.0.1',
             'web_server_port'        : 1234,
             'web_proxy'              : '127.0.0.1',
             'web_proxy_port'         : 8080,
             'capture_filter'         : None, # defined below
             'packet_filter'          : 'any',
             'field_filter'           : '.',
             'run_at_start'           : False,
             'default_breakpoint'     : None,
             'default_action'         : None,
             'default_script'         : None, }

###############################################################################
# Caching mechanism
###############################################################################


caches = list()
def cached(function):
    """Implement a generic caching decorator."""
    global caches
    cache = {}
    #keep a list of all the caches, so they can be managed
    caches.append(cache)

    @wraps(function)
    def wrapper(*args):
        key = args # this key must be hashable
        if key in cache:
            return cache[key]
        result = function(*args)
        cache[key] = result
        return result
        #
    return wrapper
    #
def cache_mng(summary = True, flush = False):
    """Manage the internal cache

    If summary is True, return a strinb telling (at least) how many
    elements the cache contains.
    If flush is True, the content of the cache will be removed, thus
    freeing memory.
    Both summary and flush can be True.
    """
    global caches
    ret = None
    if(summary):
        fct_count = len(caches)
        elem_count = 0
        for c in caches:
            elem_count += len(c)

        ret =  Template('$elen elements in cache, ' +
                        'concerning $fcount different functions')
        ret = ret.substitute(elen = elem_count, fcount = fct_count)

    if(flush):
        for c in caches:
            c.clear()

    return ret
    #

@cached
def re_compile(pattern, flags=0):
    """Provide a cached version of 're.compile()'."""
    return re.compile(pattern, flags)
    #

# shortcut
r = re_compile

###############################################################################
# Logging
###############################################################################
class LoggingFilter(logging.Filter):
    """A filter that allows any record to be processed if logging is enabled
    and only records from the main thread otherwise."""
    # Public methods ##########################################################
    def filter(self, record):
        """Determine if a given record has to be logged."""
        return shared['logging'] or record.threadName == 'MainThread'
        #
    # Private methods #########################################################
    #

class LoggingFormatter(logging.Formatter):
    """A formatter that produces a colored output based on the record logging
    level."""
    # available colors and levels
    BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(30, 38)
    COLORS = { 'ERROR'  : RED,
               'WARNING': YELLOW,
               'INFO'   : WHITE,
               'DEBUG'  : BLUE, }
    # special control sequences
    COLOR_SEQ = "\033[1;%dm"
    BOLD_SEQ = "\033[1m"
    RESET_SEQ = "\033[0m"
    # Public methods ##########################################################
    def __init__(self, *args, **kwargs):
        """Create a new formatter."""
        logging.Formatter.__init__(self, *args, **kwargs)
        #
    def format(self, record):
        """Format a given record with the appropriate colors."""
        colorvalue = LoggingFormatter.COLORS[record.levelname]
        color = LoggingFormatter.COLOR_SEQ % colorvalue
        message = logging.Formatter.format(self, record)
        message = message.replace('$COLOR', color)
        message = message.replace('$BOLD', LoggingFormatter.BOLD_SEQ)
        message = message.replace('$RESET', LoggingFormatter.RESET_SEQ)
        return message + LoggingFormatter.RESET_SEQ
        #
    # Private methods #########################################################
    #

def logging_state_on():
    """Enable logging."""
    logging_state_on.prev_logging_state = shared['logging']
    shared['logging'] = True
    #

def logging_state_off():
    """Disable logging."""
    shared['logging'] = False
    #

def logging_state_restore():
    """Restore the last logging level."""
    shared['logging'] = logging_state_on.prev_logging_state
    #

def _logging_exception():
    """Print the last exception and the associated stack traceback."""
    # retrieve information about the last exception
    exc_type, exc, exc_tb = sys.exc_info()
    findings = r(r"^<\w+\s'\w+\.(\w+)'>$").findall(str(exc_type))
    exc_type = findings[0] if findings else 'Exception'
    stack = traceback.extract_tb(exc_tb)
    stack.reverse()
    for filename, lineno, function, _ in stack:
        if filename == __file__:
            break
    else:
        filename, lineno, function, _ = stack[0]
    if exc_type == 'ParseException' and exc.loc:
        exc.msg = r(r' at .*$').sub('', exc.msg)
        exc.msg += ' at %s' % trunc_repr(exc.line[exc.loc:])
    logging_error("%s in %s: %s() => %s at line %s"
                  % (exc_type,
                     filename,
                     function,
                     exc,
                     lineno))
    # in debug mode, print the stack traceback
    if settings['effective_verbose_level'] > 1:
        # retrieve the column size for each item
        max_length = {}
        for items in stack:
            for i, item in enumerate(items):
                length = len(str(item))
                if length > max_length.get(i, 0):
                    max_length[i] = length
        # print the stack traceback
        for filename, lineno, function, line in stack:
            logging.error(("- %%-%ss  %%-%ss: %%-%ss"
                           % (max_length[0] + max_length[2] + 4,
                              max_length[1],
                              max_length[3]))
                           % ("%s: %s()" % (filename, function),
                              lineno,
                              line))
    #

def _logging_print(string=''):
    """Print a raw string to "standard error" if logging is enabled."""
    if shared['logging']:
        _logging_raw(string)
    #

def _logging_raw(string=''):
    """Print a raw string to "standard error"."""
    sys.stderr.write("\033[0m%s\033[0m\n" % string)
    sys.stderr.flush()
    #

def logging_by_lines(function):
    """Implement a decorator that logs a given message line by line."""
    @wraps(function)
    def wrapper(message):
        for line in str(message).split('\n'):
            line = line.strip()
            if len(line) > 0:
                function(line)
        #
    return wrapper
    #

# shortcuts
logging_exception = _logging_exception
logging_error     =  logging_by_lines(logging.error)
logging_warning   =  logging_by_lines(logging.warning)
logging_info      =  logging_by_lines(logging.info)
logging_debug     =  logging_by_lines(logging.debug)
logging_print     = _logging_print
logging_raw       = _logging_raw

###############################################################################
# Functions
###############################################################################

#@cached
def check_tokens(tokens, types_and_values):
    """Return the number of tokens that match the given types and values."""
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
    """Return the name of the nth network interface."""
    # retrieve devices from 'ip a'
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

#@cached
def resolv(hostname):
    """Resolve a given hostname."""
    hostname = str(hostname)
    if r(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$').match(hostname):
        try:
            socket.inet_aton(hostname)
        except socket.error:
            raise ValueError('invalid IP address: %s' %hostname)

        return [hostname]
    try:
        logging_info("querying name %s..." % trunc_repr(hostname))
        ip_addresses = resolver.query(hostname)
        if ip_addresses:
            logging_debug("name %s resolved:" % trunc_repr(hostname))
            for ip_address in ip_addresses:
                logging_debug("- %s" % trunc_repr(ip_address))
            return [str(ip_address) for ip_address in ip_addresses]
        else:
            raise ValueError("can't resolve %s" % trunc_repr(hostname))
    except:
        raise ValueError("can't resolve %s" % trunc_repr(hostname))
    #

def single_line_repr(obj):
    """Return the single line representation of a given object."""
    return r(r' *\r*\n+ *').sub(' ', str(obj)).strip()
    #

def trunc(string, max_length=50):
    """Return the truncated value of a given string."""
    default = str(string)
    if len(default) > max_length:
        result = '%s...' % default[:max_length-3].strip()
    else:
        result = default
    return result
    #

def trunc_repr(string, max_length=50):
    """Return the truncated representation of a given string."""
    default = repr(str(string))
    if len(default) > max_length:
        result = '%s...%s' % (default[:max_length-4].strip(), default[0])
    else:
        result = default
    return result
    #

###############################################################################
# Performance profiling
###############################################################################

def profile(statements, env={}, factor=1):
    """Run the given piece of code and store profiling statistics about it."""
    statements = '__profile__ = %s' % single_line_repr(statements)
    cProfile.runctx(statements, globals(), env, 'proxyshark.stats')
    try:
        for i in xrange(factor):
            profile.stats.add('proxyshark.stats')
    except AttributeError:
        profile.stats = pstats.Stats('proxyshark.stats', stream=sys.stderr)
    return env['__profile__']
    #

def profile_print(signum=None, frame=None):
    """Print profiling statistics previously generated with 'profile()'."""
    try:
        profile.stats.sort_stats('tottime')
        profile.stats.files = []
        sys.stderr.write("\n")
        profile.stats.print_stats()
        profile.stats.print_callers()
    except AttributeError:
        logging_error("no data! try to call 'profile()' first")
    finally:
        sys.stderr.flush()
        if not shared['logging']:
            sys.stdout.write("\001\033[1;34m\002>>>\001\033[37m\002 ")
            sys.stdout.flush()
    #

def profiled(function):
    """Implement a profiling decorator."""
    @wraps(function)
    def wrapper(*args, **kwargs):
        local_function = function
        return profile('local_function(*args, **kwargs)', locals())
    return wrapper
    #

# print profiling statistics when sighup is received
signal.signal(signal.SIGHUP, profile_print)

###############################################################################
# Capture filtering
###############################################################################

class Netfilter(object):
    """A set of static methods to generate and manage Netfilter rules."""
    _chain_prefix = 'PROXYSHARK'
    _existing_chains = []
    # Public methods ##########################################################
    @staticmethod
    def check_syntax(capture_filter):
        """Check the syntax of the given capture filter."""
        parser = Netfilter._capture_filter_parser()
        tokens = tuple(parser.parseString(capture_filter))
        Netfilter._process_boolean(tokens, Netfilter._process_keyword)
        #
    @staticmethod
    def apply_capture_filter():
        """Generate and apply Netfilter rules based on the current capture
        filter. A rule is a tuple composed of a chain, a condition ('iptables'
        syntax) and a target. Rules are added to the 3 main Netfilter chains
        INPUT, OUTPUT and FORWARD with NFQUEUE as a target."""
        # generate rules from the current capture filter
        capture_filter = settings['capture_filter']
        logging_info("parsing capture filter %s" % trunc_repr(capture_filter))
        parser = Netfilter._capture_filter_parser()
        tokens = tuple(parser.parseString(capture_filter))
        rules = Netfilter._process_boolean(tokens, Netfilter._process_keyword)
        # apply the rules
        logging_info("applying netfilter rules")
        table = 'filter'
        last_target = 'NFQUEUE --queue-num %s' % settings['queue_number']
        insert_rules = True
        for first_chain in ['INPUT', 'OUTPUT', 'FORWARD']:
            Netfilter._apply_rules(table,
                                   first_chain,
                                   rules,
                                   last_target,
                                   insert_rules)
            insert_rules = False # insert rules only once
        #
    @staticmethod
    def remove_rules():
        """Remove all Netfilter rules/chains in relation with Proxyshark."""
        logging_info("removing netfilter rules")
        # list all netfilter rules and chains
        iptables = Popen(['iptables', '-S'],
                         bufsize=-1,
                         stdin=None,
                         stdout=PIPE,
                         stderr=None)
        iptables_output = iptables.stdout.read()
        iptables.stdout.close()
        # remove proxyshark rules
        regex = (r'\n(-A.*(?:%s\d+|-j NFQUEUE --queue-num %s).*)'
                 % (Netfilter._chain_prefix, settings['queue_number']))
        proxyshark_rules = r(regex).findall(iptables_output)
        for proxyshark_rule in proxyshark_rules:
            Netfilter._raw_iptables(proxyshark_rule.replace('-A', '-D'))
        # remove proxyshark chains
        regex = r'\n(-N.*(?:%s\d+).*)' % Netfilter._chain_prefix
        proxyshark_chains = r(regex).findall(iptables_output)
        for proxyshark_chain in proxyshark_chains:
            Netfilter._raw_iptables(proxyshark_chain.replace('-N', '-X'))
        #
    # Private methods #########################################################
    @staticmethod
    @cached # the generator is cached, but not '_next_chain_id()' (see below)
    def __new_chain_id():
        """Return a generator of random Netfilter chain identifiers."""
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
        """Generate a random and unique Netfilter chain identifier."""
        return Netfilter.__new_chain_id().next()
        #
    @staticmethod
    @cached
    def _capture_filter_parser():
        """Return a parser for the capture filters."""
        # implement boolean expressions ('not', 'and', 'or')
        def Boolean(clause):
            parser = Forward()
            clause = Group(clause) | nestedExpr(content=parser)
            parser = operatorPrecedence(clause, [
                (Keyword('not'), 1, opAssoc.RIGHT),
                (Keyword('and'), 2, opAssoc.LEFT ),
                (Keyword('or' ), 2, opAssoc.LEFT ),])
            return parser
        # implement custom keywords
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
        keywords = ('not and or in out src dst '
                    'dev host net port ip icmp tcp udp')
        name     = NotAny(Optional('(') +
                          oneOf(keywords) +
                          (')' | White() | StringEnd()))
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
        proto    = _Keyword(None     , 'any' , None)
        proto   |= _Keyword(None     , 'ip'  , None)
        proto   |= _Keyword(None     , 'icmp', None)
        proto   |= _Keyword(None     , 'tcp' , Optional(port))
        proto   |= _Keyword(None     , 'udp' , Optional(port))
        keyword  = dev | host | net | port | proto
        parser = Optional(Boolean(keyword))
        return StringStart() + parser + StringEnd()
        #
    @staticmethod
    def _process_boolean(tokens, callback_func, callback_args=None):
        """Handle tokens describing a boolean expression. We must provide a
        callback function to handle the operands (keywords or values)."""
        # shortcut for recursive calls
        recurse = lambda tokens: Netfilter._process_boolean(tokens,
                                                            callback_func,
                                                            callback_args)
        # if we have a single list of tokens, process the elements recursively
        if check_tokens(tokens, (ParseResults,)) == 1:
            return recurse(tokens[0])
        # if we have a 'not' operator, apply a negation and process the result
        # recursively
        if check_tokens(tokens, ('not', ParseResults)) == 2:
            tokens = tokens[1]
            # not not x = x
            if check_tokens(tokens, ('not', ParseResults)) == 2:
                new_tokens = tokens[1]
                rules = recurse(new_tokens)
            # x and y = not x or not y
            elif check_tokens(tokens, (ParseResults, 'and', ParseResults)) > 2:
                new_tokens = []
                for token in tokens:
                    if token == 'and':
                        new_tokens.append('or')
                    else:
                        new_tokens.append(ParseResults(['not', token]))
                rules = recurse(new_tokens)
            # x or y = not x and not y
            elif check_tokens(tokens, (ParseResults, 'or', ParseResults)) > 2:
                new_tokens = []
                for token in tokens:
                    if token == 'or':
                        new_tokens.append('and')
                    else:
                        new_tokens.append(ParseResults(['not', token]))
                rules = recurse(new_tokens)
            # not <keyword> <value> = <keyword> not <value>
            else:
                new_tokens = []
                for token in tokens:
                    if isinstance(token, basestring):
                        new_tokens.append(token)
                    else:
                        new_tokens.append(ParseResults(['not', token]))
                rules = recurse(new_tokens)
                # if we have a single value, negate the obtained rule
                if len(new_tokens) == 1:
                    new_rules = []
                    for chain, condition, target in rules:
                        if ' -' in condition:
                            prefix, _, suffix = condition.partition(' -')
                            condition = '%s ! -%s' % (prefix, suffix)
                        else:
                            condition = '! %s' % condition
                        new_rules.append((chain, condition, target))
                    rules = new_rules
            return rules
        # if we have a 'and' operator, process each operand recursively and
        # connect the results by modifying chains and targets properly
        if check_tokens(tokens, (ParseResults, 'and', ParseResults)) > 2:
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
        if check_tokens(tokens, (ParseResults, 'or', ParseResults)) > 2:
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
        # if we have a single operand, process it with the callback function
        # with or without arguments
        if callback_args:
            return callback_func(tokens, callback_args)
        else:
            return callback_func(tokens)
        #
    @staticmethod
    def _process_keyword(tokens):
        """Handle tokens that describe a custom keyword ('dev', 'host', 'net',
        'port', etc)."""
        # if we have a single string it should be a protocol, it works also if
        # we have no filter at all
        if check_tokens(tokens, (basestring,)) == 1:
            if tokens[0] in ['ip', 'any']:
                condition = '' # nothing to do
            elif tokens[0] in ['icmp', 'tcp', 'udp']:
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
        # value or a boolean expression, so we use '_process_boolean()' with
        # '_process_value()' as a callback function
        callback_func = Netfilter._process_value
        callback_args = { 'protocol' : protocol,
                          'direction': direction,
                          'keyword'  : keyword, }
        return Netfilter._process_boolean(value, callback_func, callback_args)
        #
    @staticmethod
    def _process_value(tokens, context):
        """Handle tokens describing a single value (IP, network, etc)."""
        # retrieve context information
        protocol = context['protocol']
        direction = context['direction']
        keyword = context['keyword']
        # select the appropriate 'iptables' options
        options_by_direction = { 'in' : 0,
                                 'out': 1,
                                 'src': 0,
                                 'dst': 1, }
        options_by_keyword   = { 'dev' : ['-i', '-o'],
                                 'host': ['-s', '-d'],
                                 'net' : ['-s', '-d'],
                                 'port': ['--sport', '--dport'], }
        options = options_by_keyword[keyword]
        if direction:
            options = [options[options_by_direction[direction]]]
        # if we have a host we try to resolve its name
        if keyword == 'host':
            ip_addresses = resolv(tokens[0])
        else:
            ip_addresses = [tokens[0]]
        # if we have a port we specify for which protocol(s)
        if keyword == 'port':
            new_options = []
            for option in options:
                if protocol in ['', 'tcp']:
                    new_options.append('-p tcp %s' % option)
                if protocol in ['', 'udp']:
                    new_options.append('-p udp %s' % option)
            options = new_options
        # use the selected options to create netfilter rules, each rule is
        # composed of a chain, a condition ('iptables' syntax) and a target
        rules = []
        chain = Netfilter._new_chain_id()
        target = Netfilter._new_chain_id()
        for ip_address in ip_addresses:
            for option in options:
                condition = '%s %s' % (option, ip_address)
                rules.append((chain, condition, target))
        return rules
        #
    @staticmethod
    def _chain_replace(src_chain, dst_chain, rules):
        """Replace all occurrences of a given chain in a given ruleset."""
        new_rules = []
        for chain, condition, target in rules:
            if chain == src_chain:
                chain = dst_chain
            if target == src_chain:
                target = dst_chain
            new_rules.append((chain, condition, target))
        return new_rules
        #
    @staticmethod
    def _apply_rules(table, first_chain, rules, last_target, insert_rules=True,
                     insert_in_first_position=True, custom_condition=''):
        """Insert a ruleset in the given table. Rules must be generated by
        '_process_*()' handlers above."""
        # start by inserting the custom condition in first position
        if custom_condition:
            chain = Netfilter._new_chain_id()
            rule = (chain, custom_condition, rules[0][0])
            rules.insert(0, rule)
        # remove rules with empty conditions
        while 1:
            for chain, condition, target in rules:
                # empty condition found, replace all occurrences of the current
                # chain by the current target
                if not condition:
                    src_chain = chain
                    dst_chain = target
                    break
            else:
                # no more empty condition
                break
            if len(rules) > 1:
                # remove the found condition
                rules.remove((src_chain, '', dst_chain))
                rules = Netfilter._chain_replace(src_chain, dst_chain, rules)
            else:
                break
        # replace all occurrences of rules[0][0] by first_chain
        nb_first_chain = [chain for chain, _, _ in rules].count(rules[0][0])
        if nb_first_chain == 1:
            rules = Netfilter._chain_replace(rules[0][0], first_chain, rules)
        # replace all occurrences of rules[-1][-1] by last_target
        rules = Netfilter._chain_replace(rules[-1][-1], last_target, rules)
        # create needed proxyshark chains
        new_chains = list(set([x[0] for x in rules] + [x[2] for x in rules]))
        for new_chain in new_chains:
            if new_chain not in Netfilter._existing_chains:
                Netfilter._raw_iptables('-t %s -N %s' % (table, new_chain))
                Netfilter._existing_chains.append(new_chain)
        # remove doubles
        Netfilter._existing_chains = list(set(Netfilter._existing_chains))
        # fill the new chains if needed
        if insert_rules or len(rules) == 1:
            for chain, condition, target in rules:
                if condition:
                    condition = ' %s' % condition
                if (insert_in_first_position and
                    nb_first_chain == 1 and
                    chain == first_chain
                ):
                    args = table, chain, condition, target
                    Netfilter._raw_iptables('-t %s -I %s 1%s -j %s' % args)
                else:
                    args = table, chain, condition, target
                    Netfilter._raw_iptables('-t %s -A %s%s -j %s' % args)
        # link the first chain (the entry point) with the new rules
        if nb_first_chain > 1:
            if insert_in_first_position:
                args = table, first_chain, rules[0][0]
                Netfilter._raw_iptables('-t %s -I %s 1 -j %s' % args)
            else:
                args = table, first_chain, rules[0][0]
                Netfilter._raw_iptables('-t %s -A %s -j %s' % args)
        #
    @staticmethod
    def _raw_iptables(args):
        """Run 'iptables' command with the given arguments."""
        no_stderr = ''
        for no_display_arg in ['D', 'F', 'N', 'X']: # don't log commands
                                                    # containing these flags
            if r(r'-\b%s\b' % no_display_arg).search(args):
                no_stderr = ' 2> /dev/null'
                break
        else:
            logging_debug("iptables %s" % args)
        os.system('iptables %s%s' % (args, no_stderr))
        #
    #

###############################################################################
# Packet filtering
###############################################################################

class PacketFilter(object):
    """A set of static methods to handle packet filters."""
    # Public methods ##########################################################
    @staticmethod
    def check_syntax(packet_filter):
        """Check the syntax of the given packet filter."""
        PacketFilter._tokens_from_packet_filter(packet_filter)
        #
    @staticmethod
    def evaluate(packet, packet_filter):
        """Evaluate the given packet filter on the given packet. The result
        could be either a boolean value, a field or a set of fields depending
        on the filter passed in argument."""
        result = True
        if settings['effective_verbose_level'] > 2:
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
        if settings['effective_verbose_level'] > 2:
            logging_debug("- result = %s" % result)
        return result
        #
    @staticmethod
    def match(packet, packet_filter):
        """Return True if the given packet matches the given packet filter."""
        return bool(PacketFilter.evaluate(packet, packet_filter))
        #
    # Private methods #########################################################
    @staticmethod
    @cached
    def _packet_filter_parser():
        """Return a parser for the packet filters."""
        # implement boolean expressions ('not', 'and', 'or')
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
        parser = Optional(Boolean('any' | condition))
        return StringStart() + parser + StringEnd()
        #
    @staticmethod
    def _process_boolean(tokens, packet):
        """Handle tokens describing a boolean expression."""
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
        if check_tokens(tokens, (ParseResults, 'and', ParseResults)) > 2:
            # the slice handles the case where we have more than 2 operands
            return recurse(tokens[0], packet) and recurse(tokens[2:], packet)
        # if we have a 'or' operator, process each operand recursively
        if check_tokens(tokens, (ParseResults, 'or', ParseResults)) > 2:
            # the slice handles the case where we have more than 2 operands
            return recurse(tokens[0], packet) or recurse(tokens[2:], packet)
        # if we have a single operand, process it with '_process_condition()'
        return PacketFilter._process_condition(tokens, packet)
        #
    @staticmethod
    def _process_condition(tokens, packet):
        """Handle tokens describing a condition (an item, an optional operator
        and an optional value)."""
        # shortcut for recursive calls
        recurse = PacketFilter._process_condition
        # associate a function to each available operator
        operators = { '==': '__eq__',
                      '=' : '__eq__',
                      '!=': '__ne__',
                      '^=': 'startswith',
                      '*=': '__contains__',
                      '$=': 'endswith',
                      '<=': '__le__',
                      '<' : '__lt__',
                      '>=': '__ge__',
                      '>' : '__gt__', }
        # if we have a single list of tokens, process the elements recursively
        if check_tokens(tokens, (ParseResults,)) == 1:
            return recurse(tokens[0], packet)
        # extract the left operand, operator and value
        if check_tokens(tokens, (basestring,)) == 1:
            left_operand, operator, value = tokens[0], None, None
        elif check_tokens(tokens, (basestring,)) == 3:
            left_operand, operator, value = tokens
        else:
            raise ParseException(trunc_repr(tokens))
        # extract details from the left operand
        findings = r(r'^(?:(len|nb)\()?'    # function name
                     r'([a-z-._]+)'         # item name
                     r'(?:\[([a-z]+)\])?'   # attribute name
                     r'(?:\[([-0-9:]+)\])?' # slice key
                     r'\)?$').findall(left_operand)
        if not findings:
            raise ParseException(trunc_repr(left_operand))
        func_name, item_name, attr_name, slice_key = findings[0]
        # retrieve needed items from the packet
        if item_name == 'any':
            return True
        elif item_name == 'raw':
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
        # apply slices and remove None and 0 from the results
        operand_values = []
        for item_value in item_values:
            if slice_key:
                item_value = eval('item_value[%s]' % slice_key)
            if bool(item_value):
                operand_values.append(item_value)
        # handle special keywords
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
        # if there is no operator, return the result
        if not operator:
            return operand_values
        # otherwise, check/evaluate each operand with the appropriate function
        for operand_value in operand_values:
            # don't process None values (but 0 is allowed!)
            if operand_value is None:
                continue
            try:
                # check if the left operand is a decimal
                operand_value = repr(float(operand_value))
            except:
                # check if the left operand is an hexa
                try:
                    operand_value = str(operand_value)
                    if operand_value.startswith('0x'):
                        operand_value = float(int(operand_value, 16))
                except ValueError:
                    pass
                # in all cases, get the representation of the left operand
                operand_value = repr(operand_value)
            finally:
                # handle the case where the right operand is protected between
                # quotes (double or single)
                if value.startswith('"') and value.endswith('"'):
                    value = eval(value)
                elif value.startswith('\'') and value.endswith('\''):
                    value = eval(value)
                try:
                    # check if the right operand is a decimal
                    value = float(value)
                except:
                    # check if the right operand is an hexa
                    try:
                        value = str(value)
                        if value.startswith('0x'):
                            value = float(int(value, 16))
                    except ValueError:
                        pass
                # in all cases, get the representation of the right operand
                value = repr(value)
                # finally, compare both values with the appropriate function
                try:
                    function = operators[operator]
                    cmdline = ('%s.%s(%s)' % (operand_value, function, value))
                    result = eval(cmdline)
                    if result is NotImplemented:
                        result = False
                except:
                    logging_exception()
                    result = None
                finally:
                    if settings['effective_verbose_level'] > 2:
                        logging_debug("- eval(%s) = %s" % (cmdline, result))
            # if we have a valid result, the condition is True
            if result:
                return True
        # otherwise, the condition is False
        return False
        #
    @staticmethod
    @cached
    def _tokens_from_packet_filter(packet_filter):
        """Generate tokens from a given packet filter (see 'evaluate()')."""
        parser = PacketFilter._packet_filter_parser()
        tokens = tuple(parser.parseString(packet_filter))
        return tokens
        #
    #

###############################################################################
# Packet dissection
###############################################################################

class DissectionException(Exception):
    """A generic exception that occurs when a dissection fails."""
    pass
    #

class FieldValue(dict):
    """A class used to store the information relative to a given protocol
    or protocol field"""
    def __hash__(self):
        """Define a hash function. This was required by some methods such as
        Selection.uniq"""
        return hash(frozenset(self.items()))

class DissectedPacket(object):
    """A dissected packet as seen by Wireshark and tshark (a tree structure of
    protocols and fields)."""
    next_real_identifier = 0 # directly from tshark (-1)
    next_identifier = 0      # after packet filtering
    # Public methods ##########################################################
    def __init__(self, nfq_data, description, xml_data,
                 etree_packet):
        """Create a new dissected packet from tshark data."""
        # initialization
        self.nfq_data = nfq_data
        self.description = r(r' +').sub(' ', description).strip()
        self.xml_data = xml_data
        self.etree_packet = etree_packet
        #self.indev = network_devices(libnfq.get_indev(nfq_data))
        #self.outdev = network_devices(libnfq.get_outdev(nfq_data))
        self.modified = False
        self.verdict = None
        # create a dictionary of committed fields and a dictionary of fields
        # to commit, fields are written with 'self.__setitem__()' and
        # 'self.commit()'
        self._committed_items = {}
        self._items_to_commit = copy.deepcopy(self.read_items())
        # get raw data and packet length
        self.data = nfq_data.get_data()
        self.data_length = len(self.data)
        # get real packet identifier
        self.real_identifier = DissectedPacket.next_real_identifier
        DissectedPacket.next_real_identifier += 1
        self.identifier = None
        # retrieve packet stream identifier
        try:
            self.stream = int(self.__getitem__('tcp.stream[show]')[0])
        except:
            # this exception can be caused by 'int()' or '[0]'
            self.stream = None
        # retrieve packet attributes from the description
        regex = r'^.*(\d+\.\d+) +([^ ]+) +-> +([^ ]+) +([^ ]+) +[^ ]+ +(.*)$'
        findings = r(regex).findall(description)
        if not findings or len(findings[0]) != 5:
            raise ValueError("invalid packet description %s"
                             % trunc_repr(description))
        try:
            self.timestamp = float(findings[0][0])
        except:
            raise ValueError("invalid timestamp in packet description %s"
                             % trunc_repr(description))
        else:
            self.source = findings[0][1]
            self.destination = findings[0][2]
            self.protocol = findings[0][3]
            self.info = findings[0][4]
        #
    def __repr__(self):
        """Return a short packet description."""
        result = "Packet #%s/%s" % (self.identifier, self.real_identifier+1)
        result += " (%s)" % self._get_verdict_str()
        if self.stream is not None: # can be 0
            result += " (stream %s)" % self.stream
        result += ", %s" % self.description

        return result
        #
    def __str__(self):
        """Return a detailed packet description."""
        # commit pending items to reflect possible modifications
        self.commit()
        # retrieve the column size for each item
        items = self.read_items()
        max_length = { 'name'    : 0,
                       'value'   : 0,
                       'show'    : 0,
                       'showname': 0, }
        for item in items:
            # get item name
            item_name = item.get('name')
            if item_name:
                length = len(item_name)
                if length > max_length['name']:
                    max_length['name'] = length
            # get item value
            item_value = item.get('value')
            if item_value:
                length = len(trunc(urllib.unquote(item_value), 32))
                if length > max_length['value']:
                    max_length['value'] = length
            # get the pretty value
            item_show = item.get('show')
            if item_show:
                length = len(trunc(urllib.unquote(item_show), 64))
                if length > max_length['show']:
                    max_length['show'] = length
            # get the alternative pretty value
            item_showname = item.get('showname')
            if '.' not in item_name and item_showname:
                length = 4
                length += len(item_name)
                length += len(urllib.unquote(item_showname))
                if length > max_length['showname']:
                    max_length['showname'] = length
        # retrieve the length of the separator composed of '=' and '-'
        separator_length = 24
        separator_length += max_length['name']
        separator_length += max_length['value']
        separator_length += max_length['show']
        separator_length = max(separator_length, max_length['showname'])
        # build the result string
        result = self.__repr__()
        for item in items:
            # is it a field?
            if 'show' in item:
                pos = item.get('pos', '!ERROR!')
                size = item.get('size', '!ERROR!')
                name = item.get('name', '!ERROR!')
                show = trunc(urllib.unquote(item.get('show', '!ERROR!')), 64)
                value = trunc(urllib.unquote(item.get('value', '!ERROR!')), 32)
                result += (('\n    |   %s%%-12s %%-%ss : %%-%ss (%%s)\033[0m'
                           % ("\033[1;33m" if 'modified' in item else '',
                              max_length['name'],
                              max_length['show']))
                           % ('[%s:%s]' % (pos, str(int(pos)+int(size))),
                              name,
                              show,
                              value))
            # is it a protocol?
            else:
                name = item.get('name', '!ERROR!')
                showname = urllib.unquote(item.get('showname', '!ERROR!'))
                result += '\n    ' + '=' * separator_length
                result += '\n   + %s: %s' % (name, showname)
                result += '\n   \\' + '-' * separator_length
        result += '\n====' + '=' * separator_length
        return result
        #
    def evaluate(self, packet_filter):
        """Evaluate the given packet filter on the current packet (see
        'PacketFilter.evaluate()'). This method is equivalent to
        '__getitem__()'."""
        return PacketFilter.evaluate(self, packet_filter)

    def match(self, packet_filter):
        """Return True if the current packet matches the given packet filter
        see ('PacketFilter.match()')."""
        result = PacketFilter.match(self, packet_filter)
        # set a new identifier if needed
        if result and not self.identifier:
            self.identifier = DissectedPacket.next_identifier
            DissectedPacket.next_identifier += 1
        return result
        #
    def lookup(self, key):
        """Search items in the current packet. The key can be either a protocol
        name or a field name. It can be followed by an optional attribute name
        between brackets."""
        item_name, _, attr_name = key.partition('[')
        attr_name = attr_name.rstrip(']')
        # is it a field?
        if '.' in item_name:
            xpath = 'proto//field[@name="%s"]' % item_name
            items = self.etree_packet.findall(xpath)
        # is it a protocol?
        else:
            xpath = 'proto[@name="%s"]' % item_name
            items = self.etree_packet.findall(xpath)
            if items:
                attr_name = r(r'\bshow\b').sub('showname', attr_name)
        # return all the items or only the needed attribute
        if attr_name:
            result = [x.attrib.get(attr_name) for x in items]
        else:
            result = [FieldValue(x.attrib) for x in items]

        return result
        #
    def __iter__(self):
        """Return an iterator over the packet's protocols and fields."""
        return self.etree_packet.iter()
        #
    def __getitem__(self, packet_filter):
        """Evaluate the given packet filter on the current packet (see
        'PacketFilter.evaluate()'). This method is equivalent to
        'evaluate()'."""
        return PacketFilter.evaluate(self, packet_filter)
        #
    def __setitem__(self, field_name, new_value):
        """Set the value of a given field (the new value must be a raw string).
        The modifications must be committed with 'commit()' before setting the
        verdict or replaying the packet."""
        # ensure that we have a valid field name (without space or bracket)
        field_name = field_name.strip()
        if ' ' in field_name or field_name.endswith(']'):
            raise KeyError("key %s must be a valid field name!"
                           % trunc_repr(field_name))
        # search items with the given name
        modified = False
        for item in self._items_to_commit:
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
            KeyError("field %s was not found" % trunc_repr(field_name))
        #
    def __del__(self):
        self.drop()

    def read_items(self):
        """Return a list of dictionaries representing all the protocols and
        fields. Items are taken either from the XML tree or from the last
        committed items."""
        items = self._committed_items
        return items if items else self._read_items()
        #
    def commit(self, items_to_commit=None):
        """Apply modifications to the current packet. The optional argument can
        be a list of dictionaries representing the fields to modify. If no
        argument is provided, 'self._items_to_commit' is used instead. Finally,
        return True if the packet is successfully modified."""
        # retrieve the current items (the last committed ones)
        current_items = self.read_items()
        # retrieve the items to commit
        if not items_to_commit:
            items_to_commit = self._items_to_commit
        # skip if the packet wasn't modified
        if current_items == items_to_commit:
            #logging_debug("the packet wasn't modified, nothing to commit")
            return False
        if len(current_items) != len(items_to_commit):
            logging_error("items have inconsistent sizes (%s != %s)"
                          % (len(current_items),
                             len(items_to_commit)))
            return False
        # process each item one by one
        logging_debug("committing new items")
        if settings['effective_verbose_level'] > 2:
            logging_print("current items:")
            logging_print(repr(current_items))
            logging_print("new items:")
            logging_print(repr(items_to_commit))
        offset = 0 # global offset (in case of field size variation)
        updated_data = self.data

        item_was_modified = False
        packet_was_modified = False
        for current_item, item_to_commit in zip(current_items,
                                                items_to_commit):
            # get item name
            item_name = item_to_commit.get('name')
            if not item_name:
                logging_error("commit failed, item %s has no name"
                              % trunc_repr(item_to_commit))
                return False
            if item_name != current_item.get('name'):
                logging_error("commit failed, corrupted name (%s != %s)"
                              % (trunc_repr(item_name),
                                 trunc_repr(current_item.get('name'))))
                return False
            # ensure that we have a packet field and not a protocol (protocols
            # are not editable, they don't really contain data)
            if '.' not in item_name:
                continue
            # get item position
            item_pos = item_to_commit.get('pos')
            if not item_pos:
                logging_error("commit failed, item %s has no position"
                              % trunc_repr(item_name))
                return False
            if item_pos != current_item.get('pos'):
                logging_error("commit failed, corrupted position (%s != %s)"
                              % (trunc_repr(item_pos),
                                 trunc_repr(current_item.get('pos'))))
                return False
            try:
                item_pos = int(item_pos)
            except:
                logging_error("commit failed, invalid position %s"
                              % trunc_repr(item_pos))
                return False
            # get item size
            item_size = item_to_commit.get('size')
            if not item_size:
                logging_error("commit failed, item %s has no size"
                              % trunc_repr(item_name))
                return False
            if item_size != current_item.get('size'):
                logging_error("commit failed, corrupted size (%s != %s)"
                              % (trunc_repr(item_size),
                                 trunc_repr(current_item.get('size'))))
                return False
            try:
                item_size = int(item_size)
            except:
                logging_error("commit failed, invalid size %s"
                              % trunc_repr(item_size))
                return False
            # get item value
            item_value = item_to_commit.get('value')
            if not item_value:
                logging_error("commit failed, item %s has no value"
                              % trunc_repr(item_name))
                return False
            try:
                item_value_ascii = binascii.a2b_hex(item_value)
            except:
                logging_error("commit failed, can't unhex value %s"
                              % trunc_repr(item_value))
                return False
            # get pretty value
            item_show = item_to_commit.get('show')
            if not item_show:
                logging_error("commit failed, item %s has no pretty value"
                              % trunc_repr(item_name))
                return False
            if item_show != current_item.get('show'):
                logging_error("commit failed, corrupted pretty value "
                              "(%s != %s)"
                              % (trunc_repr(item_show),
                                 trunc_repr(current_item.get('show'))))
                return False
            # get alternative pretty value (optional)
            item_showname = item_to_commit.get('showname')
            if item_showname and item_showname != current_item.get('showname'):
                logging_error("commit failed, corrupted alternative pretty "
                              "value (%s != %s)"
                              % (trunc_repr(item_showname),
                                 trunc_repr(current_item.get('showname'))))
                return False
            # define a new value for each attribute of the current item. if the
            # current item was modified, update its position, size, value,
            # pretty value, alternative pretty value and raw data in committed
            # items and xml tree. otherwise, update only its position and size
            # to reflect the potential shift due to other field size variations
            attr_pos = str(item_pos+offset)
            attr_size = str(len(item_value_ascii))
            item_was_modified = (item_value != current_item.get('value'))
            if item_was_modified:
                packet_was_modified = True
                attr_value = item_value
                attr_show = '<<%s>>' % trunc_repr(item_value_ascii)[1:-1]
                attr_showname = ('<<%s: %s>>' # ex: '<<Src: 1.2.3.4>>'
                                 % (item_name.rpartition('.')[2].title(),
                                    trunc_repr(item_value_ascii)[1:-1]))
                # update the committed item
                item_to_commit['pos'] = attr_pos
                item_to_commit['size'] = attr_size
                #item_to_commit['value'] = attr_value # already set
                item_to_commit['show'] = attr_show
                item_to_commit['showname'] = attr_showname
                item_to_commit['modified'] = '1'
                # update the xml tree
                xpath = 'proto//field[@name=%s]' % repr(item_name)
                items = self.etree_packet.findall(xpath)
                for item in items:
                    item.set('pos', attr_pos)
                    item.set('size', attr_size)
                    item.set('value', attr_value)
                    item.set('show', attr_show)
                    if item_showname:
                        item.set('showname', attr_showname)
                    item.set('modified', '1')

                # build the new payload

                updated_data = (updated_data[:item_pos+offset] +
                                item_value_ascii +
                                updated_data[item_pos+item_size+offset:])
            else:
                # update the committed item
                item_to_commit['pos'] = attr_pos
                item_to_commit['size'] = attr_size
                # update the xml tree
                xpath = 'proto//field[@name=%s]' % repr(item_name)
                items = self.etree_packet.findall(xpath)
                for item in items:
                    item.set('pos', attr_pos)
                    item.set('size', attr_size)

            offset += len(item_value_ascii) - item_size

        # calculate the checksums of the new payload
        scapy_packet = IP(updated_data)
        scapy_packet[IP].len += offset
        del scapy_packet[IP].chksum
        scapy_packet = IP(str(scapy_packet))
        if TCP in scapy_packet:
            del scapy_packet[TCP].chksum
        if UDP in scapy_packet:
            del scapy_packet[UDP].chksum
        updated_data = str(scapy_packet)
        if settings['effective_verbose_level'] > 2:
            logging_print("current payload:")
            logging_print(repr(self.data))
            logging_print("new payload:")
            logging_print(repr(updated_data))

        # save the new payload
        self.data = updated_data
        self.data_length += offset
        # save the committed items
        self._committed_items = items_to_commit
        self._items_to_commit = copy.deepcopy(self._committed_items)

        self.modified = packet_was_modified
        # return the modification state
        return packet_was_modified
        #
    def accept(self):
        """Accept the packet."""
        self.commit()
        self._set_verdict(nfqueue.NF_ACCEPT, self.modified)
        #
    def drop(self):
        """Drop the packet."""
        self._set_verdict(nfqueue.NF_DROP)
        #
    def replay(self, layer = 3):
        """Replay this packet.

        Accepted layers are: 2, 3 4:
        - layer 2 has the behaviour of layer 3, for the moment
        - layer 3 will replay the packet starting from the IP protocol, without
        caring about any connection state.
        - layer 4 will make sure to enable a connection (if TCP is used)) before
        replaying the packet, starting from layer 4. replaying TCP at layer 4
        is currently broken."""

        def recv_udp(s):
            s.recvfrom(1500)

        def recv_tcp(s):
            s.recv(8192)


        if(layer == '' or layer == 3):
            scapy_packet = IP(self.data)
            send(scapy_packet, verbose = False)

        if(layer == 4):
            if(self.match('udp')):
                dstport = int(self['udp.dstport[value]'][0], 16)
                udp_pos = int(self['udp[pos]'][0])
                udp_size = int(self['udp[size]'][0])

                dstip = self['ip.dst[show]'][0]
                dstport = int(self['udp.dstport[value]'][0], 16)

                payload = self.data[udp_pos+udp_size:]
                try:
                    udp_socket = socket.socket(socket.AF_INET,
                                               socket.SOCK_DGRAM)

                    udp_socket.sendto(payload, (dstip, dstport))

                    #wait until a response is received, to avoid sending
                    #an ICMP port unreachable when it finally comes
                    Thread(target=recv_udp, args=(udp_socket,)).start()
                except socket.error:
                    return False

            elif(self.match('tcp')):
                dstip = self['ip.dst[show]'][0]
                dstport = int(self['tcp.dstport[value]'][0], 16)

                payload = self.get_payload('tcp')
                try:
                    tcp_socket = socket.socket(socket.AF_INET,
                                               socket.SOCK_STREAM)

                    tcp_socket.connect((dstip, dstport))

                    tcp_socket.send(payload)

                    Thread(target=recv_tcp, args=(tcp_socket,)).start()
                except socket.error:
                    return False

        return True

    def get_payload(self, proto):
        """Return the payload contained in a specified protocol"""
        ret = None
        pos = 0
        size = 0
        if(self.match(proto)):
            pos = int(self['{}[pos]'.format(proto)][0])
            size = int(self['{}[size]'.format(proto)][0])
            ret = self.data[pos+size:]

        return ret

    # Private methods #########################################################
    @cached # these items won't be updated, even if the packet is modified
    def _read_items(self):
        """Read the items from the XML tree."""
        last_proto_name = None # keep the last encountered protocol
        items = [] # [{name='...', pos='', size='', value='', show=''}, ...]
        for item in self.__iter__():
            # skip hidden items
            item_hide = item.get('hide')
            if item_hide and item_hide == 'yes':
                continue
            # get item name (can be None)
            item_name = item.get('name')
            # get item position
            item_pos = item.get('pos')
            if not item_pos:
                continue
            # get item size
            item_size = item.get('size')
            if not item_size:
                continue
            # is it a field?
            if item.tag == 'field':
                # if there is no name, use '<proto>.data' instead
                if not item_name:
                    if last_proto_name:
                        item_name = '%s.data' % last_proto_name
                        item.set('name', item_name)
                    else:
                        continue
                # apply field filter
                field_filter = settings['field_filter']
                if field_filter:
                    start = '' if '^' in field_filter else '.*'
                    end   = '' if '$' in field_filter else '.*'
                    regex = r'%s(%s)%s' % (start, field_filter, end)
                    if not r(regex).match(item_name):
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
                # get alternative pretty value (can be None)
                item_showname = item.get('showname')
                # add a new field to the item list
                if item_showname:
                    attributes = FieldValue({
                                   'name'    : item_name,
                                   'pos'     : item_pos,
                                   'size'    : item_size,
                                   'value'   : urllib.quote(item_value),
                                   'show'    : urllib.quote(item_show),
                                   'showname': urllib.quote(item_showname), })
                else:
                    attributes = FieldValue({
                                   'name' : item_name,
                                   'pos'  : item_pos,
                                   'size' : item_size,
                                   'value': urllib.quote(item_value),
                                   'show' : urllib.quote(item_show), })
                items.append(attributes)
            # is it a protocol?
            elif item.tag == 'proto':
                # a protocol must have a name
                if not item_name:
                    continue
                # get alternative pretty value
                item_showname = item.get('showname')
                if not item_showname:
                    continue
                # add a new protocol to the item list
                attributes = FieldValue({
                               'name'    : item_name,
                               'pos'     : item_pos,
                               'size'    : item_size,
                               'showname': urllib.quote(item_showname), })
                items.append(attributes)
                last_proto_name = item_name
            else:
                continue
        return items
        #
    def _set_verdict(self, verdict, modified = False):
        """Set the verdict (NF_ACCEPT or NF_DROP)."""
        if self.verdict is not None:
            raise IOError("verdict already set for packet #%s"
                          % self.identifier)
        else:
            if(modified):
                self.nfq_data.set_verdict_modified(verdict, self.data,
                                                   len(self.data))
            else:
                self.nfq_data.set_verdict(verdict)

            self.verdict = verdict
        #
    def _get_verdict_str(self):
        ret = ''
        if(self.verdict is None):
            ret = 'pending'
        elif(self.verdict == nfqueue.NF_ACCEPT):
            ret = 'accepted'
        elif(self.verdict == nfqueue.NF_DROP):
            ret = 'dropped'

        return ret
    #


class Selection(list):
        """This class defines the return type of DissectedPacketList.select

        It provides several filtering methods"""
        def uniq(self):
            luniq = lambda x: Selection(set(reduce(list.__add__, x)))
            return luniq(self)

        def sort(self):
            def _sort_getkey(e):
                if(isinstance(e, list)):
                    if(len(e) > 1):
                        e.sort()

                    key = None
                    if(isinstance(e[0], dict)):
                        if 'value' in e[0]:
                            key = 'value'
                        elif 'showname' in e[0]:
                            key = 'showname'

                    return e[0][key] if key is not None else None

            super(Selection, self).sort(key=_sort_getkey)

            return self

        def max(self):
            def _max_getkey(e):
                if(isinstance(e, list)):
                    if(isinstance(e[0], dict) and 'value' in e[0]):
                        return  max([int(x['value'], 16) for x in e])
                    else:
                        return max(e)

            return max(self, key=_max_getkey)

        def min(self):
            def _min_getkey(e):
                if(isinstance(e, list)):
                    if(isinstance(e[0], dict) and 'value' in e[0]):
                        return  min([int(x['value'], 16) for x in e])
                    else:
                        return min(e)

            return min(self, key=_min_getkey)

        def sum(self, base = 16):
            """Compute the sum of a Selection.

            Sum is available only if this selection actually contains
            digit strings. (either directly, or within the value attribute)

                ['abc', 'def']
                [{..., value:'abc'}, {...}]

            By default, the "value" key will be used to compute the sum if
            this selection contains a list of fields

            """
            def _sum_getkey(e):
                if(isinstance(e, list)):
                    if(isinstance(e[0], dict) and 'value' in e[0]):
                        return  sum([int(x['value'], base) for x in e])
                    else:
                        return sum([int(x, base) for x in e])
            pre_sum = []
            for e in self:
                pre_sum.append(_sum_getkey(e))

            return sum(pre_sum)

        def length(self):
            return len(self)


class DissectedPacketList(list):
    """A list of dissected packet."""
    # Public methods ##########################################################
    def __init__(self, *args):
        """Create a new dissected packet list."""
        self.lock = Lock()
        super(DissectedPacketList, self).__init__(*args)

    def __getitem__(self, key):
        """Evaluates 'self[key]'. The key can be a slice or a packet filter."""
        # if the key is a slice
        if isinstance(key, slice):
            # skip the first element (NotImplemented)
            if key.step is None:
                key = slice(key.start, key.stop, 1)
            if key.step >= 0:
                if not key.start:
                    key = slice(0, key.stop, key.step)
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
                try:
                    results = packet.evaluate(key)
                except AttributeError:
                    continue
                if bool(results):
                    result.append(packet)
            # return a sublist containing the packets that match
            return result
        #
        else:
            return super(DissectedPacketList, self).__getitem__(key)
        #
    def __getslice__(self, i, j):
        """Implemented for compatibiliy."""
        return self.__getitem__(slice(i, j, None))
        #
    def __repr__(self):
        """Prints the packet list as a well-formatted string."""
        return "\n".join([repr(x) for x in self])
        #
    def __str__(self):
        """Prints the packet list as a well-formatted string."""
        return "\n".join([str(x) for x in self])
        #
    def verdict(self, verdict, pfilter = None):
        """Set a verdict on all the packets matching the given filter"""

        accepted_verdict = ['accept', 'drop']
        verdict = verdict.strip().lower()
        output = None

        if(verdict.strip().lower() not in accepted_verdict):
            output = 'Verdict should be ' + ' or '.join(accepted_verdict)
        else:
            try:
                if(pfilter is None or pfilter.strip().lower() == 'all'):
                    l = self
                else:
                    l = self[pfilter]

            except Exception as e:
                print e
                output = 'Invalid packet filter'
            else:
                for p in (l):
                    if(verdict == 'accept' and p.verdict is None):
                        p.accept()
                    elif(p.verdict is None):
                        p.drop()

        return output

    def accept(self, pfilter = None):
        """Accept the packets matching the given filter"""
        return self.verdict('accept', pfilter)

    def drop(self, pfilter = None):
        """Drop the packets matching the given filter"""
        return self.verdict('drop', pfilter)

    def remove(self, arg = None):
        """remove all packets that matche the given packet filter"""

        if(isinstance(arg, DissectedPacket)):
            if(arg.verdict is None):
                arg.drop()
            super(DissectedPacketList, self).remove(arg)

        #arg is a packet filter
        elif(isinstance(arg, basestring) or arg is None):
            rc = True
            l = None

            if(arg is None or arg.strip().lower() == 'all'):
                l = DissectedPacketList(self)
            else:
                try:
                    l = DissectedPacketList(self[arg])
                except Exception as e:
                    rc = False

            self.lock.acquire()
            if(rc):
                for p in reversed(l):
                    if(p.verdict is None):
                        p.drop()
                    self.remove(p)
            self.lock.release()

            return rc

    def pending(self):
        """return all the packets without verdict"""
        return DissectedPacketList([x for x in self if x.verdict is None])

    def accepted(self):
        """return all the accepted packets"""
        return DissectedPacketList([x for x in self \
                                    if x.verdict == nfqueue.NF_ACCEPT])

    def dropped(self):
        """return all the dropped packets"""
        return DissectedPacketList([x for x in self \
                                    if x.verdict == nfqueue.NF_DROP])

    def where(self, packet_filter):
        """Return a DissectedPacketList containing all the elements matching
         packet_filter"""

        # evaluate the filter for each packet of the current list
        result = DissectedPacketList()
        for packet in self.__iter__():
            # if the evaluation matches, store the packet
            try:
                results = packet.evaluate(packet_filter)
            except AttributeError:
                continue
            if bool(results):
                result.append(packet)
        # return a list containing the packets that match
        return result

    def select(self, packet_filter):
        """Returns a list of FieldValues/strings matching the given filter

        Example: list.select('http.user_agent')"""

        result = Selection()
        item = []
        for packet in self.__iter__():
            item = packet.lookup(packet_filter)
            if(len(item) > 0):
                result.append(item)
        return result

    def length(self):
        """Return the length of this DissectedPacketList"""
        return len(self)

    def get_by_id(self, id):
        """Retrieve a packet using its identifier"""
        if(isinstance(id, int) and id >= 0):
            for p in self:
                if(p.identifier == id):
                    return p
        return None

    def replay(self, layer = 3):
        """Replay a packet list

        If layer 2 or 3 is requested, simply replay each packet one at a time.

        If layer is 4, reassemble all the tcp payload into a single tcp packet,
        and send it. UDP packets are replayed as is."""
        def recv_tcp(s):
            s.recv(8192)

        if(layer == 2 or layer == 3):
            for p in self:
                p.replay(layer)

        elif(layer == 4):
            payload = ''
            tcp = False
            for p in self:
                if p.match('udp'):
                    p.replay(layer)
                elif p.match('tcp'):
                    tcp = True
                    payload += p.get_payload('tcp')


            if(tcp):
                dstport = int(self[0]['tcp.dstport[value]'][0], 16)
                dstip = self[0]['ip.dst[show]'][0]

                try:
                    tcp_socket = socket.socket(socket.AF_INET,
                                               socket.SOCK_STREAM)

                    tcp_socket.connect((dstip, dstport))

                    tcp_socket.send(payload)

                    Thread(target=recv_tcp, args=(tcp_socket,)).start()
                except socket.error:
                    return False



class DissectedPacketSubList(DissectedPacketList):
    """A sublist of dissected packets. The only difference with the above
    packet list is that '__getitem__()' returns the item values and not the
    entire packets."""
    # Public methods ##########################################################
    def __getitem__(self, key):
        """Evaluates 'self[key]'. The key can be only a field name. Otherwise,
        the default method is used."""
        # ensure that we have a string
        if isinstance(key, basestring):
            # ensure that we have a field name (without space)
            key = key.strip()
            if ' ' in key:
                raise KeyError("key %s must be a valid field name"
                               % trunc_repr(key))
            packet_filter = key
            # evaluate the key for each packet (as a packet filter)
            result = {}
            for packet in self.__iter__():
                results = packet.evaluate(packet_filter)
                # make sure that we have a list as result, for consistency
                if not isinstance(results, list):
                    results = [results]
                result[packet.identifier] = results
            # return the list of results
            return result
        # otherwise, use the default method
        else:
            return super(DissectedPacketSubList, self).__getitem__(key)


class Dissector(object):
    """A packet dissector based on tshark."""
    # Public methods ##########################################################
    def __init__(self):
        """Create a new dissector."""
        # initialization
        self._timeout = 2
        self._tshark = {}
        # interesting events
        self._started = Event()
        self._stopping = Event()
        self._stopped = Event()
        #
    def start(self):
        """Run 2 instances of tshark: one in text mode ('-T text') to get
        general packet descriptions and another one in PDML mode ('-T pdml') to
        get detailed XML dissections."""
        if self.isAlive():
            return False
        try:
            self.__init__()
            self._start()
            return True
        except:
            logging_state_on()
            logging_exception()
            logging_state_restore()
            return False
        #
    def isAlive(self):
        """Return True if the tshark instances are running."""
        if not self._started.isSet():
            return False
        if self._stopping.isSet():
            return False
        if self._stopped.isSet():
            return False
        for mode in ['text', 'pdml']:
            tshark = self._tshark[mode]
            tshark.poll()
            if tshark.returncode >= 0:
                return False
        return True
        #
    def dissect(self, nfq_data):
        """Return a tuple composed of a short description and a 'etree.Element'
        describing the given packet."""
        if not self.isAlive():
            return None
        # get raw data and packet length
        data = nfq_data.get_data()
        data_length = len(data)

        # create a pcap header
        current_time = time.time()
        sec = int(current_time)
        usec = int((current_time - sec) * 1000000)
        packed_data_length = struct.pack('I', data_length)
        pcap_data = ''.join([struct.pack('I', sec),
                             struct.pack('I', usec),
                             packed_data_length,
                             packed_data_length,
                             data])
        # send the packet to tshark
        for mode in ['text', 'pdml']:
            self._tshark[mode].stdin.write(pcap_data)
            self._tshark[mode].stdin.flush()
        # retrieve packet description and xml dissection from tshark
        parser = XMLParser()
        description = self._tshark['text'].stdout.readline().rstrip('\n')
        readline = self._tshark['pdml'].stdout.readline
        xml_lines = []
        xml_lines_append = xml_lines.append
        parser_feed = xml_lines_append
        # wait for a starting tag
        while 1:
            line = readline()
            if line is None:
                raise DissectionException("unexpected end of file")
            if line == '<packet>\n':
                break
        # wait for an ip layer
        while 1:
            line = readline()
            if line is None:
                raise DissectionException("unexpected end of file")
            if '<proto name="ip"' in line:
                parser_feed('<packet>\n')
                parser_feed(line)
                break
        # wait for an ending tag
        while 1:
            line = readline()
            if line is None:
                raise DissectionException("unexpected end of file")
            parser_feed(line)
            if line == '</packet>\n':
                xml_data = ''.join(xml_lines)
                parser.feed(xml_data)
                break
        # return a new dissected packet
        return DissectedPacket(nfq_data,
                               description,
                               xml_data,
                               parser.close())
        #
    def stop(self):
        """Stop the tshark instances properly."""
        if not self.isAlive():
            return False
        self._stopping.set()
        for mode in ['text', 'pdml']:
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
                    time.sleep(0.1)
        logging_state_on()
        logging_info("dissector stopped")
        logging_state_restore()
        self._started.clear()
        self._stopping.clear()
        self._stopped.set()
        return True
        #
    # Private methods #########################################################
    def _start(self):
        """A wrapper that runs the tshark instances effectively."""
        # path to the tshark binary
        tshark_dir = settings['tshark_directory']
        tshark_bin = os.path.join(os.getcwd(), tshark_dir, 'tshark')
        # global pcap header
        pcap_global_header = (
            '\xd4\xc3\xb2\xa1'  # magic number
            '\x02\x00'          # major version
            '\x04\x00'          # minor version
            '\x00\x00\x00\x00'  # gmt-to-local correction
            '\x00\x00\x00\x00'  # accuracy of timestamps
            '\xff\xff\x00\x00'  # snaplen
            '\x65\x00\x00\x00') # data link type
        # tshark preferences
        preferences = ' '.join(['-o %s:%s' % (k, str(v).upper()) for k, v in [
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
            ('udp.try_heuristic_first'      , True ), ]])
        # run the tshark instances
        for mode in ['text', 'pdml']:
            tshark = Popen(('%s -i - -s0 -n -l -T %s %s'
                            % (tshark_bin,
                               mode,
                               preferences)).split(' '),
                           preexec_fn=os.setpgrp, # don't forward signals to
                                                  # tshark instances
                           bufsize=-1,
                           stdin=PIPE,
                           stdout=PIPE,
                           stderr=PIPE)
            tshark.stdin.write(pcap_global_header)
            tshark.stdin.flush()
            # try to determine if tshark is running properly
            last_line = ''
            while 1:
                line = tshark.stderr.readline().strip()
                if line:
                    last_line = line
                else:
                    msg = "An error occurred while running tshark in %s mode"
                    if last_line:
                        msg += "\ntshark said: %s" % trunc_repr(last_line)
                    raise RuntimeError(msg % mode)
                if 'capturing' in line.lower():
                    break
            self._tshark[mode] = tshark
        self._started.set()
        logging_state_on()
        logging_info("dissector started")
        logging_state_restore()
        #
    #

###############################################################################
# Local web server
###############################################################################

class ThreadingWebServer(ThreadingMixIn, HTTPServer):
    """A web server with multi-threading support."""
    # Public methods ##########################################################
    def __init__(self, server_address, RequestHandlerClass, nfqueue):
        """Create a new web server."""
        HTTPServer.__init__(self, server_address, RequestHandlerClass)
        self._nfqueue = nfqueue
        #
    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        self.RequestHandlerClass(request, client_address, self, self._nfqueue)
        #
    # Private methods #########################################################
    #

class WebServer(Thread):
    """A web server to receive and alter packets from NFQueue."""
    # Public methods ##########################################################
    def __init__(self, nfqueue):
        """Create a new web server."""
        # initialization
        Thread.__init__(self, name='WebServerThread')
        self._nfqueue = nfqueue
        self._web_server = None
        self._timeout = 2
        # interesting events
        self._started = Event()
        self._stopping = Event()
        self._stopped = Event()
        #
    def start(self):
        """Start the web server (main thread)."""
        if self.isAlive():
            return False
        self.__init__(self._nfqueue)
        Thread.start(self)
        self._started.wait(self._timeout)
        if self.isAlive():
            return True
        else:
            self._started.clear()
            self._stopping.clear()
            self._stopped.set()
            return False
        #
    def run(self):
        """Start the web server (new thread)."""
        try:
            self._run()
        except:
            logging_state_on()
            logging_exception()
            logging_state_restore()
        finally:
            logging_state_on()
            logging_info("web server stopped")
            logging_state_restore()
            self._started.clear()
            self._stopping.clear()
            self._stopped.set()
        #
    def isAlive(self):
        """Return True if the web server is running."""
        if not self._started.isSet():
            return False
        if self._stopping.isSet():
            return False
        if self._stopped.isSet():
            return False
        return True
        #
    def stop(self):
        """Stop the web server properly."""
        if not self.isAlive():
            return False
        self._stopping.set()
        self._web_server.shutdown()
        return self._stopped.wait(self._timeout)
        #
    # Private methods #########################################################
    def _run(self):
        """A wrapper that runs the web server effectively."""
        bind_address = (resolv(settings['web_server_host'])[0],
                        settings['web_server_port'])
        self._web_server = ThreadingWebServer(bind_address,
                                              WebRequestHandler,
                                              self._nfqueue)
        logging_state_on()
        logging_info("web server listening on %s:%s" % bind_address)
        logging_state_restore()
        self._started.set()
        self._web_server.serve_forever()
        self._stopping.set()
        self._web_server.socket.close()
        #
    #

class WebRequestHandler(BaseHTTPRequestHandler):
    """A handler for the HTTP requests that arrive at the web server."""
    # store the last log line to avoid flooding standard output
    _last_log = {'line': '', 'nb': 0}
    # Public methods ##########################################################
    def __init__(self, request, client_address, server, nfqueue):
        """Create a new HTTP request handler."""
        self._nfqueue = nfqueue # must be in first position because the
                                # original __init__() function never returns

        #used to specify what item was not found
        #(e.g requests regarding packets)
        self._not_found = []

        BaseHTTPRequestHandler.__init__(self, request, client_address, server)
        #
    def address_string(self):
        """Bypass default address resolution to avoid unwanted delays."""
        return self.client_address[:2][0]
        #
    def handler_request(self):
        """Handle the current HTTP request."""
        self._not_found = []
        self.params = {}

        # set the name of the current thread
        currentThread().name = 'WebRequestHandlerThread'
        # get path and parameters
        findings = r(r'^/+([^?]*)(\?.*)?$').findall(self.path)
        if not findings:
            self.send_not_found()
            return
        # check the path to avoid directory traversal
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
        # retrieve post parameters
        if not self.headers.get('Content-Length', '').isdigit():
            self.send_not_found()
            return
        length = int(self.headers['Content-Length'])
        params = self.rfile.read(length)
        for param in params.split('&'):
            name, _, value = param.partition('=')
            if(name != ''):
                self.params[name] = value
        # call the appropriate handler
        if self.path.startswith('/edit-packet/'):
            self.edit_packet()
        elif self.path.startswith('/drop-packet'):
            self.drop_packet()
        elif self.path.startswith('/remove-packet'):
            self.remove_packet()
        elif self.path.startswith('/evaluate-filter'):
            self.evaluate_filter()
        else:
            self.send_not_found()
        #
    def log_request(self, code=None, size=None):
        """Log the current HTTP request."""
        # only in debug mode
        if not settings['effective_verbose_level'] > 2:
            return
        # only if nfqueue is running
        if not self._nfqueue.isAlive():
            logging_warning("ignoring request (queue is not running)")
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
        log_line = r(r'\'_dc\': \'\d+\'').subn('', log_line)[0]
        # is it again the same line?
        last_log = WebRequestHandler._last_log
        if log_line == last_log['line']:
            last_log['nb'] += 1
        # it not, print the new one
        else:
            if last_log['nb'] > 0:
                logging_info("[repeat x%s]" % last_log['nb'])
            logging_info(log_line)
            last_log['line'] = log_line
            last_log['nb'] = 0
        # store the last log line
        WebRequestHandler._last_log = last_log
        #
    def do_GET(self):
        """Handle a GET request."""
        self.method = 'GET'
        self.send_not_found()
        #
    def do_POST(self):
        """Handle a POST request."""
        self.method = 'POST'
        self.handler_request()
        #
    def edit_packet(self):
        """Edit the specified captured packet with the received items."""
        # retrieve the packet identifier
        findings = r(r'([0-9]+)$').findall(self.path)
        if not findings:
            self.send_not_found()
            return
        identifier = int(findings[0])
        logging_info("local server received packet #%s" % identifier)

        # retrieve the packet from cache
        packet = self._nfqueue.packets.get_by_id(identifier)
        if packet is None:
            logging_error("packet #%s does not exist" % identifier)
            self._not_found.append(identifier)
            self.send_not_found()
            return

        # provide the packet with the new items
        try:
            modified = packet.commit(eval(self.params.keys()[0]))
        except:
            logging_exception()
        else:
            if modified:
                logging_info("packet #%s was successfuly modified"
                             % packet.identifier)
                if settings['effective_verbose_level'] > 1:
                    logging_print(packet)
                elif settings['effective_verbose_level'] > 0:
                    logging_print(repr(packet))
        # accept the packet
        packet.accept()
        self.send_response(200, 'OK')
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        #
    def drop_packet(self):
        identifiers = self._retrieve_identifiers()
        if(identifiers is not None):
            for i in identifiers:
                packet = self._nfqueue.packets.get_by_id(i)
                if(packet is None):
                    logging_error("packet #%s does not exist" % i)
                    self._not_found.append(i)
                else:
                    packet.drop()

        if(len(self._not_found) == 0):
            self.send_response(200, 'OK')
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
        else:
            self.send_not_found()

    def remove_packet(self):
        identifiers = self._retrieve_identifiers()
        if(identifiers is not None):
            for i in identifiers:
                packet = self._nfqueue.packets.get_by_id(i)
                if(packet is None):
                    logging_error("packet #%s does not exist" % i)
                    self._not_found.append(i)
                else:
                    self._nfqueue.packets.remove(packet)

        if(len(self._not_found) == 0):
            self.send_response(200, 'OK')
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
        else:
            self.send_not_found()

    def evaluate_filter(self):
        pfilter = self.params['filter']
        result = repr([x.identifier for x in self._nfqueue.packets[pfilter]])

        self.send_response(200, 'OK')
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(result)

    def send_not_found(self):
        """Respond with a 404 NOT FOUND error."""
        self.send_response(404, 'NOT FOUND')
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(repr(self._not_found))

        #
    # Private methods #########################################################
    #
    def _retrieve_identifiers(self):
        ids = []
        if(len(self.params) == 0):
            findings = r(r'([0-9]+)$').findall(self.path)
            if not findings:
                self.send_not_found()
                return None

            ids.append(int(findings[0]))
            logging_info("local server received packet #%s" % identifier)

        else:
            indices_str = self.params['identifiers']
            try:
                ids = literal_eval(indices_str)
                if(not isinstance(ids, list)):
                    raise TypeError("Incorrect identifiers list")
            except:
                #add something
                return

        return ids


###############################################################################
# Breakpoints - Actions
###############################################################################
class Action(object):
    """An action to be run when a packet triggers an enabled breakpoint

    Each action is bound to a single breakpoint"""

    used_aid = ['to']
    next_aid = 0
    id_pattern = re_compile(r'^[\w\-.]+$')

    def __init__(self, expression, breakpoint = None, aid = None):
        """Create a new action, with an expression.

        The action ID can be auto-generated"""
        self.code = compile(expression, '<action>', 'exec')

        if(aid == None):
            while(str(Action.next_aid) in Action.used_aid):
                Action.next_aid += 1
            aid = str(Action.next_aid)
            Action.next_aid += 1

        if(aid in Action.used_aid):
            t = Template('Action id $a already in use, or invalid')
            raise ValueError(t.substitute(a = aid))

        if(Action.is_invalid_id(aid)):
            raise ValueError('Invalid action id')

        self.id = aid
        self.breakpoint = breakpoint
        self.expression = expression
        if(self.breakpoint is not None):
            self.breakpoint.add_action(self)

        Action.used_aid.append(aid)

    def __repr__(self):
        """Return a one-line representation of this Action"""
        t = Template('Action $a, bid $b -> $exp')
        bpoint = self.breakpoint.id if self.breakpoint is not None else None
        return t.substitute(a = repr(self.id), b = repr(bpoint),
                            exp = repr(self.expression))

    def __str__(self):
        """Return a representation of this Action"""
        t = Template('  Action id: $a\n  Breakpoint id: $b\n' +
                     '  Expression: $exp')
        bpoint = self.breakpoint.id if self.breakpoint is not None else None
        return t.substitute(a = repr(self.id), b = repr(bpoint),
                            exp = repr(trunc(self.expression)))

    def add_breakpoint(self, breakpoint):
        """Set the breakpoint of this Action"""
        self.breakpoint = breakpoint

    @staticmethod
    def is_invalid_id(aid):
        return Action.id_pattern.match(aid) is None and \
               aid not in Action.used_aid

class Breakpoint(object):
    """A breakpoint triggered when a packet matches a given filter

    Breakpoints can either pause the capture, so the packet can be edited
    manually, or modify it automatically with defined action"""

    id_pattern = re_compile(r'^[\w\-.]+$')
    used_bid = ['to']
    next_bid = 0

    def __init__(self, pfilter, bid = None, enabled = False, console = None):
        """Create a new breakpoint.

        The breakpoint ID can be auto-generated"""
        #set a breakpoint id automatically if none is given
        if(bid is None):
            while(str(Breakpoint.next_bid) in Breakpoint.used_bid):
                Breakpoint.next_bid += 1
            bid = str(Breakpoint.next_bid)
            Breakpoint.next_bid += 1

        elif(bid in Breakpoint.used_bid):
            t = Template('Breakpoint id $b already in use, or invalid')
            raise ValueError(t.substitute(b = bid))

        if(Breakpoint.is_invalid_id(bid)):
            raise ValueError('Invalid breakpoint id')

        try:
            PacketFilter.check_syntax(pfilter)
        except:
            raise ValueError('Invalid packet filter')
        else:
            self._console = console
            self.packet_filter = pfilter
            self.enabled = enabled
            self.id = bid
            self.actions = list()

            Breakpoint.used_bid.append(bid)

    @staticmethod
    def is_invalid_id(bid):
        """Return True if the given id is a valid one"""
        return Breakpoint.id_pattern.match(bid) is None and \
               bid not in Breakpoint.used_bid

    def enable(self):
        """Enable this breakpoint"""
        self.enabled = True

    def disable(self):
        """Disable this breakpoint"""
        self.enabled = False

    def is_enabled(self):
        """Return True if this breakpoint is enabled"""
        return self.enabled

    def is_disabled(self):
        """Return True if this breakpoint is disabled"""
        return not self.enabled

    def would_trigger(self, packet):
        """Return 1 if this breakpoint would trigger and run at least one action

        Return 0 if it would trigger without running any action (manual editing)

        Return -1 else"""
        if(not self.enabled):
            return -1
        if(not PacketFilter.match(packet, self.packet_filter)):
            return -1
        if(len(self.actions) == 0):
            return 0

        return 1

    def try_trigger(self, packet, exec_action = True):
        """Try to trigger this breakpoint

        All of its actions will be run if the breakpoint is enabled,
        and if the given packet matches its filter

        - Return -1 if the breakpoint is disabled, or the filter does not match
        - Return 0 if there's no action to run
        - Return 1 if at least one action is run
        - Return 2 if the breakpoint matched, but exec_action was False"""
        if(not self.enabled):
            return -1
        if(not PacketFilter.match(packet, self.packet_filter)):
            return -1
        if(len(self.actions) == 0):
            return 0
        if(self._console is None):
            raise AttributeError('Console is None, cannot trigger breakpoint')

        if(exec_action):
            self._console.locals['bpkt'] = packet
            for a in self.actions:
                try:
                    exec a.code in self._console.locals
                except:
                    logging_exception()

            return 1

        return 2

    def set_console(self, console):
        """Set the console instance of this breakpoint"""
        self._console = console

    def add_action(self, a):
        """Add a new action to this breakpoint"""
        self.actions.append(a)

    def __repr__(self):
        """Return a one-line representation of this breakpoint"""

        enabled = "enabled" if self.enabled else "disabled"
        action_ids = [a.id for a in self.actions]
        t = Template('Breakpoint $bid $state, actions ($aid) -> $pf ')
        return t.substitute(bid = repr(self.id), pf = repr(self.packet_filter),
                            aid = ', '.join([repr(x) for x in action_ids]),
                            state = str(enabled))

    def __str__(self):
        """Return a multiline representation of this breakpoint"""
        action_ids = [a.id for a in self.actions]
        t = Template("Breakpoint id: $bid\n  Packet filter: $pf" +
                     "\n  Action id: $aid\n  Enabled: $state")
        return t.substitute(bid = repr(self.id), pf = repr(self.packet_filter),
                            aid = ', '.join([repr(x) for x in action_ids]),
                            state = self.enabled)

###############################################################################
# NFQueue
###############################################################################
class NFQueue(Thread):
    """A Netfilter queue that receives packets, dissects them and makes them
    available to the user."""
    # Public methods ##########################################################
    def __init__(self, console):
        """Create a new Netfilter queue."""

        self._console = console

        # initialization
        Thread.__init__(self, name='NFQueueThread')
        self.dissector = None
        self.web_server = None
        self.packets = DissectedPacketList()
        self.tmp_packets = DissectedPacketList()

        #breakpoints
        default_breakpoint = False
        self.breakpoints = dict()
        self.actions = dict()

        if(isinstance(settings['default_breakpoint'], Breakpoint)):
            self.breakpoints['default']  = settings['default_breakpoint']
            self.breakpoints['default'].set_console(self._console)
            default_breakpoint = True
        if(isinstance(settings['default_action'], Action)
           and default_breakpoint):

            self.actions['default'] = settings['default_action']
            self.actions['default'].add_breakpoint(self.breakpoints['default'])
            self.breakpoints['default'].add_action(self.actions['default'])

        self._timeout = 5
        # interesting events
        self._started = Event()
        self._stopping = Event()
        self._stopped = Event()
        self._paused = Event()
        self._unpausing = Event()
        # nfqueue settings
        self._snaplen = 65535
        self._sock_family = socket.AF_INET
        self._sock_type = 0
        # nfqueue handlers
        self._nfq_handle = None
        self._nfq_channel = None
        # re-initialize the packet identifiers
        DissectedPacket.next_real_identifier = 0
        DissectedPacket.next_identifier = 0
        #
    def __repr__(self):
        """"""
        return "<nfqueue>"
        #
    def start(self):
        """Start the capture (main thread)."""
        if self.isAlive():
            logging_warning("nfqueue already started")
            return False
        self._reinit()
        Thread.start(self)
        self._started.wait(self._timeout)
        if self.isAlive():
            return True
        else:
            self._started.clear()
            self._stopping.clear()
            self._stopped.set()
            self._paused.clear()
            return False
        #
    def run(self):
        """Start the capture (new thread)."""
        try:
            self.dissector = Dissector()
            started_dissector = self.dissector.start()
            if started_dissector and settings['web_driven']:
                self.web_server = WebServer(self)
                started_web_server = self.web_server.start()
            else:
                started_web_server = True
            if started_dissector and started_web_server:
                self._run()
        except:
            logging_state_on()
            logging_exception()
            logging_state_restore()
            self._stopping.set()
            self._started.set()
        else:
            logging_state_on()
            Netfilter.remove_rules()
            logging_state_restore()
            if self.web_server:
                self.web_server.stop()
            if self.dissector:
                self.dissector.stop()
        finally:
            logging_state_on()
            logging_info("nfqueue stopped")
            logging_state_restore()
            self._started.clear()
            self._stopping.clear()
            self._stopped.set()
            self._paused.clear()
        #
    def isAlive(self):
        """Return True if the queue is running."""
        if not self._started.isSet():
            return False
        if self._stopping.isSet():
            return False
        if self._stopped.isSet():
            return False
        return True
        #
    def isPaused(self):
        """Return True if the queue is paused."""
        return self.isAlive() and self._paused.isSet()
        #
    def isRunning(self):
        """Return True if a capture is running."""
        return self.isAlive() and not self.isPaused()
        #
    def pause(self):
        """Pause the current capture."""
        if not self.isAlive():
            logging_warning("nfqueue not started")
            return False
        if not self.isRunning():
            logging_warning("nfqueue already paused")
            return False
        self._paused.set()
        return True
        #
    def cont(self):
        """Continue the current capture.

        exit the function when a new 'manual' breakpoint triggers. Otherwise,
        merge all the packer captured during pause into the queue, and
        execute all the necessary action"""

        if(not self.isPaused):
            logging_warning('capture is not paused')
            return False
        if not self.isAlive():
            logging_warning("nfqueue not started")
            return False

        #is True if a manual breakpoint would trigger on this packet
        #This variable is used to know if we have to return : the capture
        #does not continue
        manual_trigger = False

        bpkt = self._console.locals['bpkt']

        #set a verdict on the last breakpoint packet, if necessary
        if(bpkt is not None):
            if(bpkt.verdict is None):
                bpkt.accept()

        self.packets.lock.acquire()
        for p in DissectedPacketList(self.tmp_packets):
            manual_trigger = False

            #move the first packet of the temporary list into the main queue
            self.packets.append(p)
            self.tmp_packets.remove(p)

            #figure out whether we have to return after processing this packet
            #or not. Return only if a manual breakpoint will trigger during
            #processing
            for b in self.breakpoints:
                try:
                    breakpoint = self.breakpoints[b]
                except AttributeError:
                    continue

                if(p.verdict is None):
                    if(breakpoint.would_trigger(p) == 0):
                        manual_trigger = True

            self._process_packet(p)
            if(manual_trigger):
                #make sure the lock is released before returning
                self.packets.lock.release()
                return

        #no manual breakpoint was triggered: release, unpause and return
        self.packets.lock.release()


        if(not (self._stopping.isSet() or self._stopped.isSet())):
            self._paused.clear()
            self._console.print_queue += "\001\033[0m\002Capture continuing" + \
                                         "...\n"

        return True
        #
    def stop(self):
        """Stop the queue properly.

        Do not erase the captured packet list: packets are still
        reachable until a new capture is started"""
        if not self.isAlive():
            logging_warning("nfqueue already stopped")
            return False
        self._stopping.set()
        self._paused.clear()

        if self._stopped.wait(self._timeout):
            return True
        logging_warning("waiting for nfqueue to stop...")
        return self._stopped.wait()
        #
    def close(self):
        """Close this instance of nfqueue'"""
        try:
            self._nfq_handle.unbind(socket.AF_INET)
        except Exception as e:
            #unbinding often fails somehow,
            #but seems not critical
            pass
        self._nfq_handle.close()

    def open(self):
        """Open a new netfilter queue"""
        self._nfq_handle = nfqueue.queue()

        self._nfq_handle.open()
        self._nfq_handle.bind(self._sock_family)
        self._nfq_handle.set_callback(self._callback)
        self._nfq_handle.create_queue(settings['queue_number'])
        self._nfq_handle.set_mode(nfqueue.NFQNL_COPY_PACKET)

        #use asyncore's file wrapper to make a simple integer fd
        #look like a socket object
        self._nfq_socket = asyncore.file_wrapper(self._nfq_handle.get_fd())

    def remove(self, pfilter = None):
        """empty the captured packet list

        pfilter must be a packet filter, or 'all'"""
        return self.packets.remove(pfilter)

    # Private methods #########################################################
    def _run(self):
        """A wrapper that runs a new capture effectively."""
        self.open()

        # enter the main loop
        logging_state_on()
        Netfilter.apply_capture_filter()
        logging_info("nfqueue started")
        logging_state_restore()
        self._started.set()
        try:

            while not self._stopping.isSet():
                r, w, e = select.select([self._nfq_socket], [], [], .1)
                if(len(r) > 0):
                    self._nfq_handle.process_pending(100)
            self._nfq_socket.close()

            #drop all pending packets
            for p in self.packets + self.tmp_packets:
                if(p.verdict is None):
                    p.drop()
        except:
            logging_exception()

        #the queue is stopping, so destroy it properly
        self.close()
        #
    def _callback(self, nfq_data):
        """Dissect and store the packets received from netfilter"""
        try:
            # apply the packet filter
            packet = self.dissector.dissect(nfq_data)
            if not packet: # the queue is probably stopping
                return
            if not packet.match(settings['packet_filter']):
                packet.accept()
                return

            #make sure the thread won't block indefinitely when stopping
            while(not self.packets.lock.acquire(False)):
                if(self._stopped.isSet() or self._stopping.isSet()):
                    packet.accept()
                    return
                time.sleep(.1)

            #save the first packet received during pause,
            #in order to process this packet (and the following ones)
            #when continuing
            if(self._paused.isSet()):
                self.tmp_packets.append(packet)
            else:
                self.packets.append(packet)
                self._process_packet(packet, from_shell = False)

            self.packets.lock.release()

        # accept the packet in case of error
        except:
            logging_state_on()
            logging_exception()
            logging_state_restore()
            nfq_data.set_verdict(nfqueue.NF_ACCEPT)

    def _process_packet(self, packet, from_shell = True):
        """Handle a dissected packet

        Send it to the web proxy, if web mode is enabled
        Try to trigger breakpoints
        """
        def sendrq(connection):
            try:
                # send the packet, but we don't need the response
                connection.getresponse()
            except Exception:
                pass

        if(self._stopping.isSet()):
            return

        logging_debug("nfqueue received packet #%s" % packet.identifier)
        if settings['effective_verbose_level'] > 1:
            logging_print(packet)
        elif(settings['effective_verbose_level'] > 0 or
             self._console.in_view_mode):
            logging_print(repr(packet))

        # build the item list
        items = packet.read_items()
        if not items:
            packet.accept()
            return

        # in web driven mode, send an http request to the web service
        if settings['web_driven']:
            host = '%s:%s' % (settings['web_server_host'],
                              settings['web_server_port'])
            post_headers = { 'Host'           : host,
                             'User-Agent'     : __version__,
                             'Accept-Encoding': 'identity', }
            connection = httplib.HTTPConnection(settings['web_proxy'],
                                                settings['web_proxy_port'],
                                                False,
                                                1)
            connection.request('POST',
                               'http://%s/edit-packet/%s' % (host,
                                                             packet.identifier),
                               r(r' +').sub('', repr(items)),
                               post_headers)

            #avoid blocking until timeout
            Thread(target=sendrq, args=(connection,)).start()
            return

        accept_pkt = True
        rc = -2
        for b in self.breakpoints:
            try:
                if(packet.verdict is None):
                    rc = self.breakpoints[b].try_trigger(packet)
                else:
                    accept_pkt = False
            except AttributeError:
                logging_exception()
                continue
            if(rc == 0):
                accept_pkt = False


        #accept packet, since we have either run at least one action,
        #or the packet didn't match any breakpoint
        if(accept_pkt and packet.verdict is None):
            packet.accept()
        #no action was run, but the packet matched at least one breakpoint
        else:
            #do this only for the first packet that triggers a breakpoint
            self._console.locals['bpkt'] = packet
            if(self._console.in_view_mode):
                self._console.in_view_mode = False
                #wait long enough for the main thread
                #to enter interactive mode
                time.sleep(.1)

            if(packet.verdict is None):
                output =  "\n\033[0mBreakpoint triggered. Capture paused..."
                output += '\n'+repr(packet)+'\n'
                self._console.print_queue += output

                self._paused.set()

                if(self._console.in_raw_input):
                    #make the main thread exit the raw_input function
                    #if necessary
                    signal.setitimer(signal.ITIMER_REAL, .01)
        #
    def _reinit(self):
        """Reinitialize several instance attributes

        Called before running a new capture"""
        # initialization
        Thread.__init__(self, name='NFQueueThread')
        self.dissector = None
        self.web_server = None
        self.packets = DissectedPacketList()
        self.tmp_packets = DissectedPacketList()

        self._timeout = 5

        # interesting events
        self._started = Event()
        self._stopping = Event()
        self._stopped = Event()
        self._paused = Event()

        # nfqueue handlers
        self._nfq_handle = None
        self._nfq_channel = None

        # re-initialize the packet identifiers
        DissectedPacket.next_real_identifier = 0
        DissectedPacket.next_identifier = 0


###############################################################################
# Interactive shell
###############################################################################
class Console(InteractiveConsole):
    """An interactive console to use Proxyshark from the command line."""
    # Public methods ##########################################################
    def __init__(self):
        """Create a new interactive console."""
        # initialization
        self.in_view_mode = False
        self.in_raw_input = False
        self.nfqueue = NFQueue(self)
        self._default_completer = readline.get_completer()
        readline.set_completer(self._completer)
        self._load_history()

        signal.signal(signal.SIGALRM, self._alarm_handler)
        self.print_queue = ''
        # interesting events
        self._stopping = Event()
        # readline settings
        readline.set_history_length(10*5)
        readline.parse_and_bind('set editing-mode vi')
        readline.parse_and_bind('set keymap vi-command')
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
        # build the environment
        self.current_line = ''
        self.commands = {}
        self.docstrings = {}
        for method in dir(Console):
            # is it really a command?
            findings = r(r'^_cmd_(.*)$').findall(method)
            if not findings:
                continue
            command = findings[0]
            # retrieve the doc string (short version and full text)
            docstring = eval('self.%s.__doc__' % method)
            docstring_short, _, text = docstring.partition('\n\n')
            docstring_short = r(r'\n[^\n]\s*').sub(' ', docstring_short)
            text = r(r'(^|\n) {8}').sub('\g<1>    ', text)
            # retrieve shortcuts, parameters and title
            regex = r'^\s*([a-z_|]+)\s*(.*?)\s*:\s*(.*?)\s*$'
            findings = r(regex).findall(docstring_short)
            if not findings:
                continue
            shortcuts, parameters, title = findings[0]
            # store commands and doc strings
            for shortcut in shortcuts.split('|'):
                self.commands[shortcut] = eval('self.%s' % method)
                self.docstrings[shortcut] = (shortcuts, parameters, title,
                                             text)

        InteractiveConsole.__init__(self)

        #automatically import some helper functions
        self.runsource('from binascii import unhexlify', filename = '<console>')
        self.runsource('from binascii import hexlify', filename = '<console>')
        self.runsource('from socket import inet_aton', filename = '<console>')
        self.runsource('from socket import inet_ntoa', filename = '<console>')

        #make a few methods available in the console as functions
        self.functions = ['pause', 'cont', 'continue', 'accept', 'drop', 'uniq']
        self.locals['pause'] = self._cmd_pause
        self.locals['cont'] = self._cmd_cont
        self.locals['continue'] = self._cmd_cont
        self.locals['accept'] = self._cmd_accept
        self.locals['drop'] = self._cmd_drop
        self.locals['uniq'] = self._uniq

        #instance references
        self.locals['q'] = None
        self.locals['queue'] =  None
        self.locals['nfqueue'] =  None
        self.locals['pkt'] = None
        self.locals['packet'] = None
        self.locals['bpkt'] = None
        #
    def interact(self):
        """Handle switching between view mode and interactive mode."""
        try:
            # run capture and start in interactive mode if needed
            if settings['run_at_start']:
                self._cmd_run()
                logging_print("<view mode - press Ctrl-C to jump "
                              "in interactive mode>")
            else:
                self._interact("Welcome to %s" % __version__)
            while not self._stopping.isSet():
                # view mode
                self.in_view_mode = True
                try:
                    signal.signal(signal.SIGINT, handler_sigint)
                    while not self._stopping.isSet():
                        #some other thread requests interactive mode
                        #(happens when breakpoint without action triggered)
                        if(not self.in_view_mode):
                            raise KeyboardInterrupt
                        time.sleep(0.1)
                # interactive mode
                except KeyboardInterrupt:
                    signal.signal(signal.SIGINT, signal.SIG_IGN)
                    self._interact()
        except:
            logging_exception()
        try:
            # restore signal handling
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except KeyboardInterrupt:
            pass
        # stop the capture and quit
        return self._cmd_stop() if self.nfqueue.isAlive() else True
        #
    # Private methods #########################################################
    def _load_history(self):
        """Load history from disk."""
        history_path = os.path.expanduser('~/.proxyshark_history')
        if os.path.exists(history_path):
            readline.read_history_file(history_path)
        #
    def _save_history(self):
        """Save history to disk."""
        history_path = os.path.expanduser('~/.proxyshark_history')
        readline.write_history_file(history_path)
        #
    def _completer(self, text, index):
        """Complete user's input automatically when pressing TAB key."""
        # exclude completion if text is too short
        if len(text) in (0, 1):
            return None
        result = self._default_completer(text, index)
        if result:
            # exclude private members and those containing uppercase characters
            text_length = len(text)
            private_member = result[text_length-1:text_length+1] == '._'
            uppercase_char = r(r'[A-Z]').search(result)
            if private_member or uppercase_char:
                result = self._completer(text, index+1)
            return result
        else:
            # append custom commands to the results
            default_results_max_length = 1024
            default_results = [self._default_completer(text, i) for i
                               in range(default_results_max_length)]
            result_index = index - default_results.index(None)
            results = ['%s' % key for key
                       in self.commands.keys()
                       if key.startswith(text)]

            #append the functions accessible by the user
            results +=  [x+'(' for x in self.functions
                         if x.startswith(text)]

            if result_index < len(results):
                return results[result_index]
            else:
                return None
        #
    def _command_parser(self):
        """Return a parser for the custom commands."""
        printable = alphanums + string.punctuation
        command   =  Word(string.ascii_lowercase + '_')
        slice_ctnt = printable.replace('[','').replace(']', '') + ' '
        slice = '[' + Word(slice_ctnt) + ']' | '[' + \
                                               quotedString(slice_ctnt) + ']'

        argument  = quotedString(printable ) | Word(printable)
        parser    = Optional(command + Optional(slice) + \
                    Optional(OneOrMore(argument)))
        return StringStart() + parser + StringEnd()
        #
    def try_exec(self, line):
        """Try to execute a line

        line may be composed of several expressions"""
        #will be passed to runsource

        for line in [x.strip() for x in line.split(';')]:
            # parse the line and run the appropriate command
            parser = self._command_parser()
            try:
                tokens = tuple(parser.parseString(line))
            except:
                #this line does not match the command's syntax,
                #but it coult still be a valid python expression
                try:
                    self.runsource(line, '<input>')
                except:
                    if(self.in_view_mode):
                        logging_exception()
                continue

            if len(tokens) == 1 and tokens[0] in ['x', 'exit']:
                return tokens[0]
            try:
                command = 'self.%s' % self.commands[tokens[0]].__name__
            except:
                #line is not a command, so try to execute it
                if(len(tokens) > 0):
                    try:
                        self.runsource(line, '<input>')
                    except:
                        if(self.in_view_mode):
                            logging_exception()

                continue

            arguments = []
            for token in tokens[1:]:
                if token.startswith('"') and token.endswith('"'):
                    arguments.append(repr(token[1:-1]))
                elif token.startswith('\'') and token.endswith('\''):
                    arguments.append(repr(token[1:-1]))
                elif token.strip() != '':
                    arguments.append(repr(token))
            try:
                self.current_line = line
                exec '%s(%s)' % (command, ', '.join(arguments))
            except:
                if(self.in_view_mode):
                    logging_exception()

        return

    def runsource(self, source, filename='<input>', symbol='single'):
        """Override InteractiveInterpreter.runsource

        Reset variables packet and pkt, so they point to the last
        packet received
        """
        pkt = None
        if(len(self.nfqueue.packets) > 0):
            pkt = self.nfqueue.packets[-1]

        self.locals['packet'] = pkt
        self.locals['pkt'] = pkt

        InteractiveConsole.runsource(self, source, filename, symbol)

    def _interact(self, banner=None):
        """Handle a session in interactive mode (until Ctrl-D is pressed)."""
        # print the banner
        self.in_view_mode = False
        logging_print("\033[0;34m%s" % banner if banner else "\r")
        logging_print("<interactive mode - press Ctrl-D to jump in view mode>")
        while 1:

            if(len(self.print_queue) > 0):
                sys.stdout.write(self.print_queue)
                self.print_queue = ''
                sys.stdout.flush()
            try:
                # wait for the next command from the user
                logging_state_off()
                line = ''
                self.in_raw_input = True
                line = self.raw_input("\001\033[1;34m\002>>>\001\033[37m\002 ")
                self.in_raw_input = False
                sys.stderr.write("\001\033[0m\002")
                sys.stderr.flush()
            except EOFError:
                # ctrl-d was pressed, switch to view mode
                self._save_history()
                logging_state_on()
                logging_print("\n<view mode - press Ctrl-C to jump "
                              "in interactive mode>")
                break
            except KeyboardInterrupt:
                self.in_raw_input = False
                pass

            if(line is not None):
                ret = self.try_exec(line)
                if(ret in ('x', 'exit')):
                    self._save_history()
                    self._stopping.set()

                    #drop all pending packets
                    self._cmd_verdict("drop", "all")
                    return
        #
    def _alarm_handler(self, signum, frame):
        """Raise KeyboardInterrupt whenever SIGALRM is catched

        This is a work-around to exit the raw_input function when necessary.
        Console.interact MUST be run by the main thread in order
        to make it work"""
        raise KeyboardInterrupt

    def _cmd_help(self, command=None):
        """h|help [<command>] : print a short help describing the available
        commands

        <command> : you can give an optional command name to get detailed
                    description about it"""
        # build a list of selected commands
        commands = [command] if command else ['help', 'info', 'set', 'run',
                                              'pause', 'cont', 'stop', 'flush',
                                              'remove', 'breakpoint', 'action',
                                              'enable', 'disable', 'pending',
                                              'verdict', 'accept', 'drop',
                                              'queue', 'pkt', 'bpkt']
        # check commands availability and retrieve max length of the left part
        max_length = 0
        for command in commands:
            if command in self.docstrings:
                shortcuts, parameters, title, text = self.docstrings[command]
                length = len(shortcuts) + len(parameters) + 1
                if length > max_length:
                    max_length = length
            else:
                logging_error("command %s does not exist"
                              % trunc_repr(command))
                return
        # print doc strings of selected commands
        logging_state_on()
        for command in commands:
            shortcuts, parameters, title, text = self.docstrings[command]
            docstring = (('%%-%ss : %%s' % max_length)
                         % ('%s %s' % (shortcuts, parameters),
                            title))
            logging_print(docstring)
            if len(commands) == 1:
                logging_print()
                logging_print(text)
        logging_print()
        logging_state_restore()
        #
    def _cmd_info(self, *args):
        """i|info : print information about the current program state

        Available parmeters are:

        * verbosity
        * ethernet
        * queue-num
        * tshark-dir
        * web-driven
        * bind ip
        * bind port
        * proxy ip
        * proxy port
        * capture filter
        * packet filter
        * field filter
        * breakpoints
        * actions
        * cache"""

        def info_verbosity():
            return 'Verbose level: %s' % (settings['effective_verbose_level'])

        def info_ethernet():
            return 'Ethernet mode: %s' % (repr(settings['ethernet_layer']))

        def info_queue_num():
            return 'Queue number: %s' % (settings['queue_number'])

        def info_tshark_dir():
            return 'tshark directory: %s' % (settings['tshark_directory'])

        def info_web_driven():
            return 'Web driven mode: %s' % (settings['web_driven'])

        def info_bind_ip():
            return 'Bind IP: %s' % (settings['web_server_host'])

        def info_bind_port():
            return 'Bind port: %s' % (settings['web_server_port'])

        def info_proxy_ip():
            return 'Proxy IP: %s' % (settings['web_proxy'])

        def info_proxy_port():
            return 'Proxy port: %s' % (settings['web_proxy_port'])

        def info_capture_filter():
            return 'Capture filter: %s' % repr((settings['capture_filter']))

        def info_packet_filter():
            return 'Packet filter: %s' % repr((settings['packet_filter']))

        def info_field_filter():
            return 'Field filter: %s' % repr((settings['field_filter']))

        def info_breakpoints():
            breakpoints = self.nfqueue.breakpoints
            if(len(breakpoints) > 0):
                breakpoints_repr = [repr(breakpoints[k]) for k in breakpoints]
                return 'Breakpoints: \n*' + '\n*'.join(breakpoints_repr)
            return ''

        def info_actions():
            actions = self.nfqueue.actions
            if(len(actions) > 0):
                actions_repr = [trunc(repr(actions[k])) for k in actions]
                return 'Actions: \n*' + '\n*'.join(actions_repr)
            return ''

        def info_cache():
            return 'Cache: ' + cache_mng(summary = True)

        output = ''
        parameter = None
        param_found = False
        param_list = [
            'verbosity',
            'ethernet',
            'queue-num',
            'tshark-dir',
            'web-driven',
            'bind ip',
            'bind port',
            'proxy ip',
            'proxy port',
            'capture filter',
            'packet filter',
            'field filter',
            'breakpoints',
            'actions',
            'cache'
        ]

        if(len(args) > 0):
            parameter = args[0]
            if(not parameter in param_list):
                for i in range(1, len(args)):
                    parameter += ' '+args[i]

                    if(parameter in param_list):
                        param_found = True
                        break
            else:
                param_found = True

            if(not param_found):
                parameter = None

        if(parameter is not None):
            parameter = parameter.strip()
        #display all
        if(parameter is None):
            web = 'disabled'
            tp_web = None
            tp = None
            actions_str = 'None'
            breakpoints_str = 'None'

            if(len(self.nfqueue.actions) > 0):
                actions = self.nfqueue.actions
                actions_repr = [repr(actions[k]) for k in actions]
                actions_str = '\n- ' + '\n- '.join(actions_repr)

            if(len(self.nfqueue.breakpoints) > 0):
                breakpoints = self.nfqueue.breakpoints
                breakpoints_repr = [repr(breakpoints[k]) for k in breakpoints]
                breakpoints_str = '\n- ' + '\n- '.join(breakpoints_repr)

            tp_str  = "Current settings:\n"
            tp_str += "- verbose level      = $v\n"
            tp_str += "- ethernet layer     = $e\n"
            tp_str += "- queue number       = $q\n"
            tp_str += "- tshark directory   = $t\n"
            tp_str += "- web driven         = $w\n"
            tp_str += "- capture filter     = $c\n"
            tp_str += "- packet filter      = $p\n"
            tp_str += "- field filter       = $f\n"
            tp_str += "- cache content      = $cache\n\n"
            tp_str += "Breakpoints: $b\n\n"
            tp_str += "Actions: $a"

            tp = Template(tp_str)

            if(settings['web_driven']):
                tp_web = Template("enabled\n" +
                                  "- web server         = $sh:$sp\n" +
                                  "- web proxy          = $wh:$wp")
                web = tp_web.substitute(
                    sh = settings['web_server_host'],
                    sp = settings['web_server_port'],
                    wh = settings['web_proxy'],
                    wp = settings['web_proxy_port']
                )

            output = tp.substitute(
                v = settings['real_verbose_level'],
               e = settings['ethernet_layer'],
               q = settings['queue_number'],
               t = trunc_repr(settings['tshark_directory']),
               w = web,
               c = trunc_repr(settings['capture_filter']),
               p = trunc_repr(settings['packet_filter']),
               f = trunc_repr(settings['field_filter']),
               b = breakpoints_str,
               a = actions_str,
               cache = cache_mng(summary = True)
            )

        #unknown
        elif(not parameter in param_list):
            output = 'Unknown parameter %s' % (parameter)
        #known
        else:
            #spaces and '-' are not allowed in function names
            fparameter = parameter.replace(' ', '_').replace('-', '_')
            info_fct = eval('info_%s' % (fparameter))
            output = info_fct()

        if(len(output) > 0):
            logging_state_on()
            logging_print(output)
            logging_state_restore()
        #
    def _cmd_set(self, *args):
        """set <parameter> <value> : set the value of a given parameter

        * set verbosity <0|1|2|3>: set the verbosity level to one of the
        following values:
            0 for errors only (quiet mode)
            1 for information and warnings
            2 for debug
            3 for debug, raw data and XML dissection


        * set ethernet <off|on|0|1>: if enabled, an Ethernet layer will be
        automatically generated for all captured packets.
        Otherwise, packets will start at layer 3 (IP).Enabling this mode
        is required only if you plan to replay packets at layer 2


        * set queue-num <queue-num>: this option specifies which queue to use
        and to send the queue'd data to. The queue number is a 16 bit
        unsigned integer, which means it can take any value between 0 and 65535


        * set tshark-dir <tshark-dir>: set the location of the tshark binary
        to use for packet dissection. If not found, tshark is taken from $PATH


        * set web-driven <off|on|0|1>: in this mode, an embedded web server will
        wait for incoming requests from proxyshark itself. The idea is to ask
        proxyshark to call this web service each time a packet is captured
        so that we can use a tool such as Burp Suite Pro to handle it


        * set bind ip <bind-ip> | set bind port <bind-port>
         set proxy ip <proxy-ip> | set proxy port <proxy-port>: set parameters
        of the web-driven mode


        * set capture filter <capture-filter>: set the current capture filter.
        This filter acts at a netfilter level to select which packets
        have to be captured. Basically, you just have to provide a BPF filter
        and proxyshark will use it to generate appropriate iptables rules
        targeting the NFQUEUE target


        * set packet filter <packet-filter>: set the current packet filter.
        This filter is almost like a Wireshark display filter. You can use it
        to select captured packets based on dissection criteria


        * set field filter <field-filter>: set the current field filter.
        This filter is only available in web-driven mode. It's just a
        regular expression to select which protocols and fields are sent to
        the web proxy (ie which ones will be editable/repeatable
        through the GUI).
        Note that if no ^ or $ characters are found, they will be automatically
        added at the beginning or at the end of the filter.
        """
        def set_verbosity(value):
            global settings
            accepted_val = [str(x) for x in range(0,4)]

            if(not value in accepted_val):
                t =  Template('Accepted value are: $v')
                return t.substitute(v = ', '.join(accepted_val))

            ivalue = int(value)
            settings['effective_verbose_level'] = ivalue
            return None

        def set_ethernet(value):
            global settings
            accepted_val = {
                'off': False,
                '0': False,
                'on': True,
                '1': True
            }
            value = value.lower()
            if(value not in accepted_val):
                t =  Template('Accepted value are: $v')
                return t.substitute(v = ', '.join(accepted_val.keys()))

            settings['ethernet_layer'] = accepted_val[value]
            return None

        def set_queue_num(value):
            global settings
            if self.nfqueue.isAlive():
                return 'Cannot change queue number while capture is running'
            try:
                ivalue = int(value)
                if(ivalue < 0 or ivalue > 65535):
                    raise ValueError
            except ValueError:
                return 'Bad value, or out of range (0-65535)'
            settings['queue_number'] = ivalue
            return None

        def set_tshark_dir(directory):
            if self.nfqueue.isAlive():
                return 'Cannot change tshark directory while capture is running'

            candidate = os.path.join(directory, 'tshark')
            t = None
            if os.path.isfile(candidate):
                settings['tshark_directory'] = os.path.dirname(candidate)
            elif not os.path.isdir(directory):
                return  "Directory not found"
            else:
                return "Cannot find tshark in this directory"

            return None

        def set_web_driven(state):
            global settings
            states = {
                'off': False,
                '0': False,
                'on': True,
                '1': True
            }
            state = state.lower()

            if self.nfqueue.isAlive():
                return 'Cannot (un)set web-driven mode while capture is running'

            if(state in states):
                settings['web_driven'] = accepted_val[state]

            else:
                #user is trying to set IP/ports
                split = state.split(':')
                if len(split) == 4:
                    # web server host
                    if split[0]:
                        if resolv(split[0]):
                            settings['web_server_host'] = split[0]
                        else:
                            return "invalid web server host"
                    # web server port
                    if split[1]:
                        if (split[1].isdigit() and
                            int(split[1]) > 0 and int(split[1]) <= 65535
                        ):
                            settings['web_server_port'] = int(split[1])
                        else:
                            return "invalid web server port"
                    # web proxy host
                    if split[2]:
                        if split[2] and resolv(split[2]):
                            settings['web_proxy'] = split[2]
                        else:
                            return "invalid web proxy host"
                    # web proxy port
                    if split[3]:
                        if (split[3].isdigit() and
                            int(split[3]) > 0 and int(split[3]) <= 65535
                        ):
                            settings['web_proxy_port'] = int(split[3])
                        else:
                            return "invalid web proxy port"
                    #
                    settings['web_driven'] = True
                else:
                    t =  Template('Accepted value are: $v, '
                                 '[<server-host>]:[<server-port>]:'
                                 '[<proxy-host>]:[<proxy-port>]')

                    return t.substitute(v = ', '.join(states.keys()))
            return None

        def set_bind_ip(host):
            global settings
            if(self.nfqueue.isAlive()):
                return 'Cannot change bind ip while capture is running'
            try:
                resolv(host)
            except ValueError:
                return 'Could not resolv host, or invalid ip'
            else:
                settings['web_server_host'] = host
            return None

        def set_bind_port(port):
            global settings
            if(self.nfqueue.isAlive()):
                return 'Cannot change bind port while capture is running'

            try:
                iport = int(port, base=10)
                if(iport < 1 or iport > 65535):
                    raise ValueError()

            except ValueError:
                return 'Invalid port number'

            settings['web_server_port'] = iport
            return None

        def set_proxy_ip(host):
            global settings
            if(self.nfqueue.isAlive()):
                return 'Cannot change proxy ip while capture is running'
            try:
                resolv(host)
            except ValueError:
                return 'Could not resolv host, or invalid ip'
            except Exception as e:
                print e
            else:
                settings['web_proxy'] = host
            return None

        def set_proxy_port(port):
            global settings
            if(self.nfqueue.isAlive()):
                return 'Cannot change proxy port while capture is running'

            try:
                iport = int(port, base=10)
                if(iport < 1 or iport > 65535):
                    raise ValueError()

            except ValueError:
                return 'Invalid port number'

            settings['web_proxy_port'] = iport
            return None

        def set_capture_filter(cfilter):
            try:
                Netfilter.check_syntax(cfilter)
            except(ParseBaseException):
                return 'Invalid capture filter'

            settings['capture_filter'] = cfilter

            return None

        def set_packet_filter(pfilter):
            try:
                PacketFilter.check_syntax(pfilter)
                settings['packet_filter'] = pfilter
            except(ParseBaseException):
                return 'Invalid packet filter'

        def set_field_filter(ffilter):
            output = None
            try:
                re_compile(ffilter)
            except re.error as e:
                t = Template('Invalid field filter: $err')
                output = t.substitute(err = trunc(e.message))
            else:
                settings['field_filter'] = ffilter
            return output

        output = None
        parameter = None
        param_found = False
        value = None
        param_list = [
            'verbosity',
            'ethernet',
            'queue-num',
            'tshark-dir',
            'web-driven',
            'bind ip',
            'bind port',
            'proxy ip',
            'proxy port',
            'capture filter',
            'packet filter',
            'field filter'
        ]

        if(len(args) > 0):

            parameter = args[0]
            if(not parameter in param_list):
                for i in range(1, len(args)):
                    parameter += ' '+args[i]

                    if(parameter in param_list):
                        param_found = True
                        value = ' '.join(args[i+1:])
                        break
            else:
                param_found = True
                value = ' '.join(args[1:])

            if(not param_found):
                parameter = None


        if(parameter is None):
            output = 'Available parameters:\n    $params'
            t = Template(output)
            output = t.substitute(params=',\n    '.join(param_list))
        elif(len(value.strip()) > 0):
            parameter = parameter.strip()
            if(value is None):
                output = 'Value is missing'
            elif(not parameter in param_list):
                output = 'Unknown parameter'
            else:
                value = value.strip()

                #spaces and '-' are not allowed in function names
                fparameter = parameter.replace(' ', '_').replace('-', '_')
                info_fct = eval('set_%s' % (fparameter))
                output = info_fct(value)

        if(output is not None):
            logging_state_on()
            logging_print(output)
            logging_state_restore()
        #
    def _cmd_run(self, capture_filter=None, packet_filter=None,
                 field_filter=None):
        """r|run [<capture-filter>] [<packet-filter>] [<field-filter>] : run a
        new capture (drop previously captured packets)"""
        try:
            if capture_filter:
                Netfilter.check_syntax(capture_filter)
                settings['capture_filter'] = capture_filter
        except ParseException, exception:
            exception.msg = "invalid capture filter"
            raise exception
        try:
            if packet_filter:
                PacketFilter.check_syntax(packet_filter)
                settings['packet_filter'] = packet_filter
        except ParseException, exception:
            exception.msg = "invalid packet filter"
            raise exception
        try:
            if field_filter:
                re.compile(field_filter)
                settings['field_filter'] = field_filter
        except:
            raise ParseException("invalid field filter")
        result = self.nfqueue.start()
        if result:
            logging_state_on()
            logging_print("Capture started...")
            logging_state_restore()

        #refresh instance references
        self.locals['q'] = self.nfqueue.packets
        self.locals['queue'] =  self.nfqueue.packets
        self.locals['nfqueue'] =  self.nfqueue.packets
        self.locals['pkt'] = None
        self.locals['packet'] = None
        self.locals['bpkt'] = None
        return result
        #
    def _cmd_pause(self):
        """p|pause : pause the current capture"""
        result = self.nfqueue.pause()
        if result:
            logging_state_on()
            logging_print("Capture paused.")
            logging_state_restore()
        return result
        #
    def _cmd_cont(self):
        """c|cont : continue the current capture"""
        self.nfqueue.cont()
        #
    def _cmd_stop(self):
        """s|stop : stop the current capture (drop previously captured
        packets)"""
        result = self.nfqueue.stop()
        if result:
            logging_state_on()
            logging_print("Capture stopped.")
            logging_state_restore()

        return result
        #
    def _cmd_flush(self):
        """f|flush : flush internal cache to free memory (captured packets are
        not removed)"""
        cache_mng(summary=False, flush=True)
        #
    def _cmd_rm(self, pfilter = None):
        """rm|remove [<packet-filter>]: remove packets from queue

        <packet-filter> must be a valid packet filter, or 'all'"""
        if(not self.nfqueue.remove(pfilter)):
            logging_state_on()
            logging_print('Invalid packet filter')
            logging_state_restore()

    def _cmd_breakpoint(self, operation = None, bid = None,
                        packet_filter = None):
        """b|breakpoint [add|del] [<breakpoint-id>] [<packet-filter>]: display,
        add or delete a new breakpoint

        Breakpoints are triggered when a given packet filter matches a
        captured packet. In view mode, you need to define
        an action to be run when the breakpoint is triggered.
        In interactive mode, you can either define an action
        or alter the packet manually, accept it, drop it, replay it, etc.

        *If no argument is given, print a list of all existing breakpoints
        (equivalent to info breakpoints)

        *If <breakpoint-id> is given, print the packet filter associated
        to this breakpoint. The breakpoint identifier must be an
        arbitrary string containing letters, digits, dashes, dots or underscores

        *If add, <breakpoint-id> and <packet-filter> are given, create a new
        breakpoint based on the given identifier and filter.

        *If add and <packet-filter> are given, create a new breakpoint and name
        it automatically

        *If del and <breakpoint-id> are given, delete the breakpoint

        Examples:

        >>> breakpoint
        >>> breakpoint bpid
        >>> breakpoint add bp_icmp icmp"""

        #the user did not request any legal operation: the operation parameter
        #should actually contain a breakpoint id
        if(operation != 'add' and operation != 'del' and bid is None):
            bid = operation
            operation = None

        breakpoints = self.nfqueue.breakpoints

        logging_state_on()
        if(operation is None):
            if(bid is None):
                #print every breakpoints
                self._cmd_info('breakpoints')
            else:
                #display only the packet filter
                try:
                    output = self.nfqueue.breakpoints[bid].packet_filter
                    logging_print(repr(output))
                except:
                    logging_print('Unknown breakpoint id')

        else:
            if(operation == 'add' and bid is not None):

                #in this case, no bid was specified. Current bid is actually
                #a packet filter
                #the breakpoint ID will be chosen automatically
                if(packet_filter is None):
                    packet_filter = bid
                    bid = None

                try:
                    b = Breakpoint(packet_filter, bid, enabled = True,
                                   console = self)
                    breakpoints[b.id] = b
                except ValueError as e:
                    logging_print(e.message)

            elif(operation == 'del' and bid is not None):
                try:
                    bpoint = self.nfqueue.breakpoints[bid]
                except KeyError:
                    logging_print('Unknown breakpoint id')
                else:
                    for a in bpoint.actions:
                        a.breakpoint = None

                    del bpoint.actions[:]
                    del self.nfqueue.breakpoints[bid]
                    del bpoint

                    Breakpoint.used_bid.remove(bid)

            else:
                logging_print('Invalid call')

        logging_state_restore()

    def _cmd_enable(self, bid):
        """en|enable <breakpoint-id>: enable an existing breakpoint"""
        try:
            self.nfqueue.breakpoints[bid].enabled = True
        except KeyError:
            logging_state_on()
            logging_print('Unknown breakpoint id')
            logging_state_restore()

    def _cmd_disable(self, bid):
        """dis|disable <breakpoint-id>: disable an existing breakpoint"""
        try:
            self.nfqueue.breakpoints[bid].enabled = False
        except KeyError:
            logging_state_on()
            logging_print('Unknown breakpoint id')
            logging_state_restore()

    def _cmd_action(self, operation = None, aid = None, to = None, bid = None,
                    *expr):
        """a|action [add|del|bind|unbind] [<action-id>] [to] [<breakpoint-id>]
        [<expressions> ...]: display, add, bind or unbind an action

        Actions are Python expressions to be run when a breakpoint is triggered.
        Commands available in interactive mode are also
        available in such expressions.

        *If no argument is given, print a list of all existing actions
        (equivalent to info actions).

        *If only an action identifier is given, print the breakpoint
        and the Python expression associated to this action
        The action identifier must be an arbitrary string containing
        letters, digits, dashes, dots or underscores.

        *If del and an action id are given, delete an existing action

        *If bind, an action id and a breakpoint id are given, rebind an existing
        action to an existing breakpoint

        *If unbind, and an action id are given, unbind an
        existing action from an existing breakpoint

        *If add, an action id, the keyword 'to', a breakpoint id and
        expressions, are given, create a new action based on the given
        expressions and identifiers, and bind it to the breakpoint.
        If the action id is omitted, the action will be named automatically.
        The keyword 'to' and the breakpoint id can also be omitted: this will
        create a new action, without binding it do any breakpoint

        Examples:

        >>> action add a1 "some expression" #do not bind
        >>> action add to default "expr1" "expr2" "expr3"
        >>> action add a2 to default "print 'triggered!'"
        >>>
        >>> action bind a1 default
        >>> action unbind a1
        >>>
        >>> action del a2"""

        operations = ['add', 'del', 'bind', 'unbind']

        #the user did not request any legal operation: the operation parameter
        #should actually contain an action id
        if(operation not in operations and aid is None):
            aid = operation
            operation = None


        logging_state_on()
        if(operation is None):
            #print every actions
            if(aid is None):
                if (bid is None):
                    self._cmd_info('actions')

            #print the requested action, and its breakpoint
            else:
                try:
                    action = self.nfqueue.actions[aid]
                    breakpoint = action.breakpoint
                    expr = action.expression
                except KeyError as e:
                    logging_print('Unknown action id')
                else:
                    t = Template('$b\n\n$e')
                    logging_print(t.substitute(b=str(breakpoint), e=repr(expr)))

        elif(operation == 'add'):
            if(to != 'to'):
                #usage: action add to bid
                if(aid == 'to'):
                    aid = None
                    expr = [bid] + list(expr)
                    bid = to
                    try:
                        b = self.nfqueue.breakpoints[bid]
                    except KeyError as k:
                        logging_print('Unknown breakpoint id')
                        return
                else:
                    #usage: action add aid expr
                    expr = [to] + [bid] + list(expr)
                    to = None
                    b = None

                expr = [x for x in expr if x is not None]
            else:
                #add aid to bid expr
                try:
                    b = self.nfqueue.breakpoints[bid]
                except KeyError as k:
                    b = None

            #create a new action
            if(expr is not None):
                try:
                    #unescape the expressions
                    expr = [x.decode('string_escape') for x in expr]
                    a = Action('\n'.join(expr), b, aid)
                    self.nfqueue.actions[a.id] = a
                except:
                    logging_exception()

        elif(operation == 'del'):
            try:

                self._cmd_action('unbind', aid)

                action = self.nfqueue.actions[aid]
            except KeyError:
                logging_print('Unknown action id')
            else:
                try:
                    #remove action aid from actions dictionnary,
                    #delete action object
                    del self.nfqueue.actions[aid]
                    del action

                except:
                    #the association has already been removed
                    pass

                Action.used_aid.remove(aid)

        elif(operation == 'bind'):
            if(bid == None):
                bid = to

            try:
                a = self.nfqueue.actions[aid]
            except KeyError:
                logging_print('Unknown action id')

            else:
                try:
                    b = self.nfqueue.breakpoints[bid]
                except KeyError as k:
                    logging_print('Unknown breakpoint id')
                else:
                    b.add_action(a)
                    a.breakpoint = b

        elif(operation == 'unbind'):
            try:
                action = self.nfqueue.actions[aid]
            except KeyError:
                logging_print('Unknown action id')
            else:
                try:
                    #remove action in breakpoint,
                    #and breakpoint in action
                    action.breakpoint.actions.remove(action)
                    action.breakpoint = None
                except:
                    #the association has already been removed
                    pass
        else:
            logging_print('Unknown command')

        logging_state_restore()

    def _cmd_pending(self):
        """pe|pending : returns a list of all packets without verdict"""
        pe_list = [x for x in self.nfqueue.packets if x.verdict is None]
        self.locals['_'] = DissectedPacketList(pe_list)
        self.runsource('_', '<console>')

    def _cmd_accept(self, pfilter = None):
        """acc|accept [<packet-filter>]: accept packets matching the given
        filter

        <packet-filter> can be None, 'all', or any packet filter"""
        self._cmd_verdict('accept', pfilter)

    def _cmd_drop(self, pfilter = None):
        """dr|drop [<packet-filter>]: drop packets matching the given filter

        <packet-filter> can be None, 'all', or any packet filter"""
        self._cmd_verdict('drop', pfilter)

    def _cmd_verdict(self, verdict, pfilter = None):
        """v|verdict <accept|drop> <packet-filter>: set a given verdict to
        all packets matching the given filter

        Accepted verdicts are: 'accept', 'drop'
        packet-filter can be None, 'all', or any packet filter"""
        output = self.nfqueue.packets.verdict(verdict, pfilter)
        if(output):
            logging_state_on()
            logging_print(output)
            logging_state_restore()

    def _cmd_queue(self, *args):
        """q|queue|nfqueue: a reference to the captured packet list"""
        self.runsource(self.current_line, filename = '<console>')

    def _cmd_pkt(self, *args):
        """pkt|packet: a reference to the last captured packet"""
        self.runsource(self.current_line, filename = '<console>')

    def _cmd_bpkt(self, *args):
        """bpkt: a reference to the last packet that triggered a breakpoint"""
        self.runsource(self.current_line, filename = '<console>')

    def _uniq(self, packet_filter):
        """Shortcut for queue.select(filter).uniq()

        This method will be reachable through the function uniq() from
        the interactive shell."""
        return self.nfqueue.packets.select(packet_filter).uniq()

###############################################################################
# Main entry point
###############################################################################

def print_usage():
    usage = """%s

    Usage: %s [arguments] with optional arguments within:

        -h | --help

        -v | --verbose

        -e | --ethernet-layer

        -q | --queue-number <queue-number>

        -t | --tshark-directory <tshark-directory>

        -w | --web-driven [<web-server-host>]:[<web-server-port>]:
                          [<web-proxy-host>]:[<web-proxy-port>]

        -c | --capture-filter <capture-filter>

        -p | --packet-filter <packet-filter>

        -f | --field-filter <field-filter>

        -r | --run-at-start

        -b | --default-breakpoint <packet-filter>

        -a | --default-action <python-expression>

        [<default-script>]


        See https://code.google.com/p/proxyshark/ for further instructions.

    """ % (__version__, __file__)
    logging_print(r(r'\n    ').sub('\n', usage))
    #

def process_arguments():
    # search a directory containing a tshark binary
    locations = ['bin/%s/' % os.uname()[4]]
    locations += os.environ.get('PATH', '').split(os.pathsep)
    for location in locations:
        candidate = os.path.join(location, 'tshark')
        if os.path.isfile(candidate):
            settings['tshark_directory'] = os.path.dirname(candidate)
            break
    # parse the command line arguments
    opts, args = getopt.getopt(sys.argv[1:],
                               'hveq:t:w:c:p:f:rb:a:',
                               ['help',
                                'verbose',
                                'ethernet-layer',
                                'queue-number=',
                                'tshark-directory=',
                                'web-driven=',
                                'capture-filter=',
                                'packet-filter=',
                                'field-filter=',
                                'run-at-start',
                                'default-breakpoint=',
                                'default-action=',])
    # -h | --help
    if ('-h', '') in opts or ('--help', '') in opts:
        print_usage()
        sys.exit(0)
    for opt, arg in opts:
        # -e | --ethernet
        if opt in ['-e', '--ethernet-layer']:
            settings['ethernet_layer'] = True
        # -q | --queue-number <queue-number>
        elif opt in ['-q', '--queue-number']:
            if arg.isdigit() and int(arg) >= 0 and int(arg) <= 65535:
                settings['queue_number'] = int(arg)
            else:
                raise ValueError("invalid queue number %s" % trunc_repr(arg))
        # -t | --tshark-directory <tshark-directory>
        elif opt in ['-t', '--tshark-directory']:
            candidate = os.path.join(arg, 'tshark')
            if os.path.isfile(candidate):
                settings['tshark_directory'] = os.path.dirname(candidate)
            elif not os.path.isdir(arg):
                raise ValueError("directory %s not found" % trunc_repr(arg))
            else:
                raise ValueError("tshark not found in %s" % trunc_repr(arg))
        # -w | --web-driven [<web-server-host>]:[<web-server-port>]:
        #                   [<web-proxy-host>]:[<web-proxy-port>]
        elif opt in ['-w', '--web-driven']:
            split = arg.split(':')
            if len(split) == 4:
                # web server host
                if split[0]:
                    if resolv(split[0]):
                        settings['web_server_host'] = split[0]
                    else:
                        raise ValueError("invalid web server host")
                # web server port
                if split[1]:
                    if (split[1].isdigit() and
                        int(split[1]) > 0 and int(split[1]) <= 65535
                    ):
                        settings['web_server_port'] = int(split[1])
                    else:
                        raise ValueError("invalid web server port")
                # web proxy host
                if split[2]:
                    if split[2] and resolv(split[2]):
                        settings['web_proxy'] = split[2]
                    else:
                        raise ValueError("invalid web proxy host")
                # web proxy port
                if split[3]:
                    if (split[3].isdigit() and
                        int(split[3]) > 0 and int(split[3]) <= 65535
                    ):
                        settings['web_proxy_port'] = int(split[3])
                    else:
                        raise ValueError("invalid web proxy port")
                #
                settings['web_driven'] = True
            else:
                raise ValueError("invalid web server/proxy specification")
        # -c | --capture-filter <capture-filter>
        elif opt in ['-c', '--capture-filter']:
            Netfilter.check_syntax(arg)
            settings['capture_filter'] = arg
        # -p | --packet-filter <packet-filter>
        elif opt in ['-p', '--packet-filter']:
            PacketFilter.check_syntax(arg)
            settings['packet_filter'] = arg
        # -f | --field-filter <field-filter>
        elif opt in ['-f', '--field-filter']:
            re.compile(arg)
            settings['field_filter'] = arg
        # -r | --run-at-start
        elif opt in ['-r', '--run-at-start']:
            settings['run_at_start'] = True
        # -b | --default-breakpoint <packet-filter>
        elif opt in ['-b', '--default-breakpoint']:
            try:
                settings['default_breakpoint'] = Breakpoint(arg,
                                                            'default',
                                                            True)
            except:
                logging_exception()
        # -a | --default-action <expression>
        elif opt in ['-a', '--default-action']:
            #add a new action, without any breakpoint
            try:
                settings['default_action'] = Action(arg, None, 'default')
            except:
                logging_exception()
    # ensure that we have a tshark directory
    if not settings['tshark_directory']:
        raise ValueError("tshark was not found")
    # default capture filter
    if not settings['capture_filter']:
        if settings['web_driven']:
            settings['capture_filter'] = (
                '(not (src host %s and tcp src port %s) and '
                ' not (dst host %s and tcp dst port %s) and '
                ' not (src host %s and tcp src port %s) and '
                ' not (dst host %s and tcp dst port %s))'
                % (settings['web_server_host'],
                   settings['web_server_port'],
                   settings['web_server_host'],
                   settings['web_server_port'],
                   settings['web_proxy'],
                   settings['web_proxy_port'],
                   settings['web_proxy'],
                   settings['web_proxy_port']))
        else:
            settings['capture_filter'] = 'any'
    # default script to run at start
    if len(args) > 0:
        raise NotImplementedError("scripts are not implemented yet")
        #FIXME: args[0] can contain more than one argument
        settings['default_script'] = args[0]
    # print current settings

    bp_filter = settings['default_breakpoint'].packet_filter \
                if settings['default_breakpoint'] \
                else 'None'

    a_expr = settings['default_action'].expression \
            if settings['default_action'] \
            else 'None'

    logging_info("""
        Current settings:
        - verbose level      = %s
        - ethernet layer     = %s
        - queue number       = %s
        - tshark directory   = %s
        - web driven         = %s%s
        - capture filter     = %s
        - packet filter      = %s
        - field filter       = %s
        - run at start       = %s
        - default breakpoint = %s
        - default action     = %s
        - default script     = %s
    """ % (
        settings['real_verbose_level'],
        settings['ethernet_layer'],
        settings['queue_number'],
        trunc_repr(settings['tshark_directory']),
        settings['web_driven'],
        """\n - web server         = %s:%s
              - web proxy          = %s:%s
        """ % (
            settings['web_server_host'],
            settings['web_server_port'],
            settings['web_proxy'],
            settings['web_proxy_port'],
        ) if settings['web_driven'] else "",
        trunc_repr(settings['capture_filter']),
        trunc_repr(settings['packet_filter']),
        trunc_repr(settings['field_filter']),
        settings['run_at_start'],
        trunc_repr(bp_filter),
        trunc_repr(a_expr),
        settings['default_script'],
    ))
    #

if __name__ == '__main__':
    try:
        result = None
        # configure the logging system
        settings['real_verbose_level'] = (sys.argv.count('-v') +
                                          sys.argv.count('--verbose'))
        logging_level = { 0: logging.WARNING,
                          1: logging.INFO,
                          2: logging.DEBUG,
        }.get(settings['real_verbose_level'], logging.DEBUG)
        shared['logger'] = logging.getLogger()
        shared['logger'].setLevel(logging_level)
        handler = logging.StreamHandler()
        formatter = LoggingFormatter("%%(asctime)s %s "
                                     "Proxyshark(%%(process)s): "
                                     "%%(threadName)s: "
                                     "$COLOR[%%(levelname)s] "
                                     "%%(message)s$RESET"
                                     % socket.gethostname())
        handler.setFormatter(formatter)
        shared['logger'].addHandler(handler)
        shared['logger'].addFilter(LoggingFilter())
        settings['effective_verbose_level'] = settings['real_verbose_level']
        logging_state_on()
        # check if we have root permissions
        if os.getuid() != 0:
            raise RuntimeError("permission denied")
        # process command line arguments
        process_arguments()
        # start interactive console
        result = Console().interact()
    except SystemExit:
        result = True
    except:
        logging_exception()
    finally:
        logging.shutdown()
        sys.exit(0 if result is True else 1)
