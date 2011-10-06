-- init.lua
--
-- initialize wireshark's lua
--
--  This file is going to be executed before any other lua script.
--  It can be used to load libraries, disable functions and more.
--
-- $Id: template-init.lua 25176 2008-04-25 19:04:52Z jake $
--
-- Wireshark - Network traffic analyzer
-- By Gerald Combs <gerald@wireshark.org>
-- Copyright 1998 Gerald Combs
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

-- Lua is disabled by default, comment out the following line to enable Lua support.
disable_lua = true; do return end;


-- If set and we are running with special privileges this setting
-- tells whether scripts other than this one are to be run.
run_user_scripts_when_superuser = false


-- disable potentialy harmful lua functions when running superuser
if running_superuser then
    local disabled_lib = {}
    setmetatable(disabled_lib,{ __index = function() error("this package has been disabled") end } );

    dofile = function() error("dofile has been disabled") end
    loadfile = function() error("loadfile has been disabled") end
    loadlib = function() error("loadlib has been disabled") end
    require = function() error("require has been disabled") end
    os = disabled_lib
    io = disabled_lib
    file = disabled_lib
end

-- to avoid output to stdout which can cause problems lua's print ()
-- has been suppresed so that it yields an error.
-- have print() call info() instead.
if gui_enabled() then
    print = info
end

-- -- Wiretap encapsulations
wtap = {
	["UNKNOWN"] = 0,
	["ETHERNET"] = 1,
	["TOKEN_RING"] = 2,
	["SLIP"] = 3,
	["PPP"] = 4,
	["FDDI"] = 5,
	["FDDI_BITSWAPPED"] = 6,
	["RAW_IP"] = 7,
	["ARCNET"] = 8,
	["ARCNET_LINUX"] = 9,
	["ATM_RFC1483"] = 10,
	["LINUX_ATM_CLIP"] = 11,
	["LAPB"] = 12,
	["ATM_PDUS"] = 13,
	["ATM_PDUS_UNTRUNCATED"] = 14,
	["NULL"] = 15,
	["ASCEND"] = 16,
	["ISDN"] = 17,
	["IP_OVER_FC"] = 18,
	["PPP_WITH_PHDR"] = 19,
	["IEEE_802_11"] = 20,
	["PRISM_HEADER"] = 21,
	["IEEE_802_11_WITH_RADIO"] = 22,
	["IEEE_802_11_WLAN_RADIOTAP"] = 23,
	["IEEE_802_11_WLAN_AVS"] = 24,
	["SLL"] = 25,
	["FRELAY"] = 26,
	["FRELAY_WITH_PHDR"] = 27,
	["CHDLC"] = 28,
	["CISCO_IOS"] = 29,
	["LOCALTALK"] = 30,
	["OLD_PFLOG"] = 31,
	["HHDLC"] = 32,
	["DOCSIS"] = 33,
	["COSINE"] = 34,
	["WFLEET_HDLC"] = 35,
	["SDLC"] = 36,
	["TZSP"] = 37,
	["ENC"] = 38,
	["PFLOG"] = 39,
	["CHDLC_WITH_PHDR"] = 40,
	["BLUETOOTH_H4"] = 41,
	["MTP2"] = 42,
	["MTP3"] = 43,
	["IRDA"] = 44,
	["USER0"] = 45,
	["USER1"] = 46,
	["USER2"] = 47,
	["USER3"] = 48,
	["USER4"] = 49,
	["USER5"] = 50,
	["USER6"] = 51,
	["USER7"] = 52,
	["USER8"] = 53,
	["USER9"] = 54,
	["USER10"] = 55,
	["USER11"] = 56,
	["USER12"] = 57,
	["USER13"] = 58,
	["USER14"] = 59,
	["USER15"] = 60,
	["SYMANTEC"] = 61,
	["APPLE_IP_OVER_IEEE1394"] = 62,
	["BACNET_MS_TP"] = 63,
	["NETTL_RAW_ICMP"] = 64,
	["NETTL_RAW_ICMPV6"] = 65,
	["GPRS_LLC"] = 66,
	["JUNIPER_ATM1"] = 67,
	["JUNIPER_ATM2"] = 68,
	["REDBACK"] = 69,
	["NETTL_RAW_IP"] = 70,
	["NETTL_ETHERNET"] = 71,
	["NETTL_TOKEN_RING"] = 72,
	["NETTL_FDDI"] = 73,
	["NETTL_UNKNOWN"] = 74,
	["MTP2_WITH_PHDR"] = 75,
	["JUNIPER_PPPOE"] = 76,
	["NETTL_X25"] = 79,
	["K12"] = 80,
	["JUNIPER_MLPPP"] = 81,
	["JUNIPER_MLFR"] = 82,
	["JUNIPER_ETHER"] = 83,
	["JUNIPER_PPP"] = 84,
	["JUNIPER_FRELAY"] = 85,
	["JUNIPER_CHDLC"] = 86,
	["JUNIPER_GGSN"] = 87,
	["LINUX_LAPD"] = 88,
	["CATAPULT_DCT2000"] = 89,
	["BER"] = 90,
	["JUNIPER_VP"] = 91,
	["USB"] = 92,
	["IEEE802_16_MAC_CPS"] = 93,
	["NETTL_RAW_TELNET"] = 94,
	["USB_LINUX"] = 95,
	["MPEG"] = 96,
	["PPI"] = 97,
	["ERF"] = 98,
	["BLUETOOTH_H4_WITH_PHDR"] = 99,
	["SITA"] = 100,
	["SCCP"] = 101,
	["BLUETOOTH_HCI"] = 102,
	["IPMB"] = 103,
	["IEEE802_15_4"] = 104,
	["X2E_XORAYA"] = 105,
	["FLEXRAY"] = 106,
	["LIN"] = 107,
	["MOST"] = 108,
	["CAN20B"] = 109,
	["LAYER1_EVENT"] = 110,
	["X2E_SERIAL"] = 111,
	["I2C"] = 112,
	["IEEE802_15_4_NONASK_PHY"] = 113,
	["TNEF"] = 114,
	["USB_LINUX_MMAPPED"] = 115,
	["GSM_UM"] = 116,
	["DPNSS"] = 117,
	["PACKETLOGGER"] = 118
}


--  -- Field Types
ftypes = {
	["NONE"] = 0,
	["PROTOCOL"] = 1,
	["BOOLEAN"] = 2,
	["UINT8"] = 3,
	["UINT16"] = 4,
	["UINT24"] = 5,
	["UINT32"] = 6,
	["UINT64"] = 7,
	["INT8"] = 8,
	["INT16"] = 9,
	["INT24"] = 10,
	["INT32"] = 11,
	["INT64"] = 12,
	["FLOAT"] = 13,
	["DOUBLE"] = 14,
	["ABSOLUTE_TIME"] = 15,
	["RELATIVE_TIME"] = 16,
	["STRING"] = 17,
	["STRINGZ"] = 18,
	["EBCDIC"] = 19,
	["UINT_STRING"] = 20,
	["ETHER"] = 21,
	["BYTES"] = 22,
	["UINT_BYTES"] = 23,
	["IPv4"] = 24,
	["IPv6"] = 25,
	["IPXNET"] = 26,
	["FRAMENUM"] = 27,
	["PCRE"] = 28,
	["GUID"] = 29,
	["OID"] = 30
}


-- -- Display Bases
 base = {
	["NONE"] = 0,
	["DEC"] = 1,
	["HEX"] = 2,
	["OCT"] = 3,
	["DEC_HEX"] = 4,
	["HEX_DEC"] = 5,
}



-- -- Expert flags and facilities
PI_SEVERITY_MASK = 3584
PI_CHAT = 512
PI_NOTE = 1024
PI_WARN = 1536
PI_ERROR = 2048
PI_GROUP_MASK = 4294963200
PI_CHECKSUM = 4096
PI_SEQUENCE = 8192
PI_RESPONSE_CODE = 16384
PI_REQUEST_CODE = 20480
PI_UNDECODED = 32768
PI_REASSEMBLE = 65536
PI_MALFORMED = 131072
PI_DEBUG = 262144




-- -- menu groups for register_menu
MENU_ANALYZE_UNSORTED = 0
MENU_ANALYZE_CONVERSATION = 1
MENU_STAT_UNSORTED = 2
MENU_STAT_GENERIC = 3
MENU_STAT_CONVERSATION = 4
MENU_STAT_ENDPOINT = 5
MENU_STAT_RESPONSE = 6
MENU_STAT_TELEPHONY = 7
MENU_TOOLS_UNSORTED = 8


-- other useful constants
GUI_ENABLED = gui_enabled()
DATA_DIR = datafile_path()
USER_DIR = persconffile_path()

dofile("console.lua")
--dofile("dtd_gen.lua")
