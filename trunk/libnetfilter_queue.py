#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# This file is part of proxyshark, a tool designed to dissect and alter IP
# packets on-the-fly. This file was taken from python-libnetfilter-queue:
# http://code.google.com/p/python-libnetfilter-queue by Andres Lopez Luksenberg
# <alopezluksenberg@gmail.com>.
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

# imports

import ctypes

import ctypes.util as utils

from socket import ntohl

# load library
nflib = utils.find_library('netfilter_queue')
assert nflib, 'you need netfilter_queue lib'
netfilter = ctypes.cdll.LoadLibrary(nflib)

###############################################################################
# Structs
###############################################################################

class nfq_handle (ctypes.Structure):
	pass

class nfq_q_handle(ctypes.Structure):
	pass

class nfq_data(ctypes.Structure):
	pass

class nfqnl_msg_packet_hw(ctypes.Structure):
	_fields_ = [("hw_addrlen", ctypes.c_uint16),
	            ("_pad", ctypes.c_uint16),
	            #############################
	            ("hw_addr", ctypes.c_uint8 * 8)]

class nfqnl_msg_packet_hdr(ctypes.Structure):
	_fields_ = [('packet_id', ctypes.c_uint32),
	            ('hw_protocol', ctypes.c_uint16),
	            ('hook', ctypes.c_uint8)]

class nfnl_handle(ctypes.Structure):
	_fields_ = [('fd', ctypes.c_int),
	            ('subscriptions', ctypes.c_uint32),
	            ('seq', ctypes.c_uint32),
	            ('dump', ctypes.c_uint32),
	            ('rcv_buffer_size', ctypes.c_uint32),
	            #####################################
	            ('local', ctypes.c_void_p),
	            ('peer', ctypes.c_void_p),
	            ('last_nlhdr', ctypes.c_void_p),
	            ('subsys', ctypes.c_void_p)]

_call = ctypes.CFUNCTYPE(
	ctypes.c_int, *(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)
)

class nfnl_callback(ctypes.Structure):
	_fields_ = [('call', _call),
	            ('data', ctypes.c_void_p),
	            ('attr_count', ctypes.c_uint16)]

class nfnl_subsys_handle(ctypes.Structure):
	_fields_ = [('nfilter_handler', ctypes.POINTER(nfnl_handle)),
	            ('subscriptions', ctypes.c_uint32),
	            ('subsys_id', ctypes.c_uint8),
	            ('cb_count', ctypes.c_uint8),
	            ('callback', ctypes.POINTER(nfnl_callback))]

class nlif_handle(ctypes.Structure):
	_fields_ = [('ifindex_max', ctypes.c_void_p),
	            ('rtnl_handle', ctypes.c_void_p),
	            ('ifadd_handler', ctypes.c_void_p),
	            ('ifdel_handler', ctypes.c_void_p)]

time_t = ctypes.c_long
suseconds_t = ctypes.c_long

class timeval(ctypes.Structure):
	_fields_ = [('tv_sec', time_t),
	            ('tv_usec', suseconds_t)]

class nfq_handle(ctypes.Structure):
	_fields_ = [('nfnlh', ctypes.POINTER(nfnl_handle)),
	            ('nfnlssh', ctypes.POINTER(nfnl_subsys_handle)),
	            ('qh_list', ctypes.POINTER(nfq_q_handle))]

class nfq_q_handle( ctypes.Structure):
	_fields_ = [('next', ctypes.POINTER(nfq_q_handle)),
	            ('h', ctypes.POINTER(nfq_handle)),
	            ('id', ctypes.c_uint16),
	            ('cb', ctypes.c_void_p),
	            ('data', ctypes.c_void_p)]

class nfq_data(ctypes.Structure):
	_fields_ = [('data', ctypes.POINTER(ctypes.c_void_p))]

###############################################################################
# Responses from callback
###############################################################################

NF_DROP, NF_ACCEPT, NF_STOLEN = 0, 1, 2
NF_QUEUE, NF_REPEAT, NF_STOP = 3, 4, 5
NF_MAX_VERDICT = NF_STOP

###############################################################################
# Mode
###############################################################################

NFQNL_COPY_NONE, NFQNL_COPY_META, NFQNL_COPY_PACKET = 0, 1, 2

###############################################################################
# Functions
###############################################################################

# return netfilter netlink handler
nfnlh = netfilter.nfq_nfnlh
nfnlh.restype = ctypes.POINTER(nfnl_handle)
nfnlh.argtypes = ctypes.POINTER(nfq_handle),

# return a file descriptor for the netlink connection associated with the
# given queue connection handle.
nfq_fd = netfilter.nfnl_fd
nfq_fd.restype = ctypes.c_int
nfq_fd.argtypes = ctypes.POINTER(nfnl_handle),

# this function obtains a netfilter queue connection handle
ll_open_queue = netfilter.nfq_open
ll_open_queue.restype = ctypes.POINTER(nfq_handle)

# this function closes the nfqueue handler and free associated resources
close_queue = netfilter.nfq_close
close_queue.restype = ctypes.c_int
close_queue.argtypes = ctypes.POINTER(nfq_handle),

# bind a nfqueue handler to a given protocol family
bind_pf = netfilter.nfq_bind_pf
bind_pf.restype = ctypes.c_int
bind_pf.argtypes = ctypes.POINTER(nfq_handle), ctypes.c_uint16 

# unbind nfqueue handler from a protocol family
unbind_pf = netfilter.nfq_unbind_pf
unbind_pf.restype = ctypes.c_int
unbind_pf.argtypes = ctypes.POINTER(nfq_handle), ctypes.c_uint16

# create a new queue handle and returns it
create_queue = netfilter.nfq_create_queue
create_queue.restype = ctypes.POINTER(nfq_q_handle)
create_queue.argtypes = ctypes.POINTER(nfq_handle), \
	ctypes.c_uint16, ctypes.c_void_p, ctypes.c_void_p

# remove the binding for the specified queue handle
destroy_queue = netfilter.nfq_destroy_queue
destroy_queue.restype = ctypes.c_int
destroy_queue.argtypes = ctypes.POINTER(nfq_q_handle),

# triggers an associated callback for the given packet received from the queue
handle_packet = netfilter.nfq_handle_packet
handle_packet.restype = ctypes.c_int
handle_packet.argtypes = \
	ctypes.POINTER(nfq_handle), ctypes.c_char_p, ctypes.c_int

# set the amount of data to be copied to userspace for each packet queued to
# the given queue:
#   - NFQNL_COPY_NONE  : do not copy any data
#   - NFQNL_COPY_META  : copy only packet metadata
#   - NFQNL_COPY_PACKET: copy entire packet
set_mode = netfilter.nfq_set_mode
set_mode.restype = ctypes.c_int
set_mode.argtypes = ctypes.POINTER(nfq_q_handle), ctypes.c_uint8, ctypes.c_uint

# set the size of the queue in kernel. This fixes the maximum number of packets
# the kernel will store before internally before dropping upcoming packets
set_queue_maxlen = netfilter.nfq_set_queue_maxlen
set_queue_maxlen.restype = ctypes.c_int
set_queue_maxlen.argtypes = ctypes.POINTER(nfq_q_handle), ctypes.c_uint32

# notifies netfilter of the userspace verdict for the given packet, every
# queued packet _must_ have a verdict specified by userspace, either by calling
# this function or by calling the nfq_set_verdict_mark() function
#   - NF_DROP       : drop packet
#   - NF_ACCEPT     : accept packet
#   - NF_STOLEN     : don't continue to process the packet, don't deallocate it
#   - NF_QUEUE      : enqueue the packet
#   - NF_REPEAT     : handle the same packet
#   - NF_STOP       : ?
#   - NF_MAX_VERDICT: ?
set_verdict = netfilter.nfq_set_verdict
set_verdict.restype = ctypes.c_int
set_verdict.argtypes = ctypes.POINTER(nfq_q_handle), \
	ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_char_p

# like set_verdict, but you can set the mark
set_verdict_mark = netfilter.nfq_set_verdict_mark
set_verdict_mark.restype = ctypes.c_int
set_verdict_mark.argtypes = ctypes.POINTER(nfq_q_handle), ctypes.c_uint32, \
	ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_char_p

get_msg_packet_hdr = netfilter.nfq_get_msg_packet_hdr
get_msg_packet_hdr.restype = ctypes.POINTER(nfqnl_msg_packet_hdr)
get_msg_packet_hdr.argtypes = ctypes.POINTER(nfq_data),

# return the netfilter mark currently assigned to the given queued packet
get_nfmark = netfilter.nfq_get_nfmark
get_nfmark.restype = ctypes.c_uint32
get_nfmark.argtypes = ctypes.POINTER(nfq_data),

# retrieves the received timestamp when the given queued packet
get_timestamp = netfilter.nfq_get_timestamp
get_timestamp.restype = ctypes.c_int
get_timestamp.argtypes = ctypes.POINTER(nfq_data), ctypes.POINTER(timeval)

# return the index of the device the queued packet was received via, if the
# returned index is 0, the packet was locally generated or the input interface
# is not known
get_indev = netfilter.nfq_get_indev
get_indev.restype = ctypes.c_uint32
get_indev.argtypes = ctypes.POINTER(nfq_data),

# return the index of the physical device the queued packet was received via,
# if the returned index is 0, the packet was locally generated or the physical
# input interface is no longer known
get_physindev = netfilter.nfq_get_physindev
get_physindev.restype = ctypes.c_uint32
get_physindev.argtypes = ctypes.POINTER(nfq_data),

# return the index of the device the queued packet will be sent out
get_outdev = netfilter.nfq_get_outdev
get_outdev.restype = ctypes.c_uint32
get_outdev.argtypes = ctypes.POINTER(nfq_data),

# return the index of physical interface where the packet will be routed out
get_physoutdev = netfilter.nfq_get_physoutdev
get_physoutdev.restype = ctypes.c_uint32
get_physoutdev.argtypes = ctypes.POINTER(nfq_data),

# retrieves the hardware address associated with the given queued packet
get_packet_hw = netfilter.nfq_get_packet_hw
get_packet_hw.restype = ctypes.POINTER(nfqnl_msg_packet_hw)
get_packet_hw.argtypes = ctypes.POINTER(nfq_data),

# retrieve the payload for a queued packet
get_payload = netfilter.nfq_get_payload
get_payload.restype = ctypes.c_int
get_payload.argtypes = ctypes.POINTER(nfq_data), ctypes.POINTER(ctypes.c_void_p)

HANDLER = ctypes.CFUNCTYPE(
	None,
	*(ctypes.POINTER(nfq_q_handle),
	ctypes.c_void_p,
	ctypes.POINTER(nfq_data),
	ctypes.c_void_p)
)

def open_queue():
	handler = ll_open_queue()
	handler != None, "can't open the queue"
	return handler

def get_full_payload(nfa):
	ptr_packet = ctypes.c_void_p(0)
	len_recv = get_payload(nfa, ctypes.byref(ptr_packet));
	data = ctypes.string_at(ptr_packet, len_recv)
	return len_recv, data

def get_full_msg_packet_hdr(nfa):
	pkg_hdr = get_msg_packet_hdr(nfa)
	return {
		'packet_id' : ntohl(pkg_hdr.contents.packet_id),
		'hw_protocol' :  ntohl(pkg_hdr.contents.hw_protocol),
		'hook' : pkg_hdr.contents.hook
	}

def set_pyverdict(queue_handle, packet_id, verdict, buffer_len, buffer):
	set_verdict(
		queue_handle, packet_id, verdict, buffer_len, ctypes.c_char_p(buffer)
	)

def get_pytimestamp(nfa):
	mtime = timeval()
	get_timestamp(nfa, ctypes.byref(mtime))
	return mtime.tv_sec, mtime.tv_usec

