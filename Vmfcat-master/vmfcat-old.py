#!/usr/bin/env python
#
# Copyright (C) 2015 Jonathan Racicot
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http:#www.gnu.org/licenses/>.
#
# You are free to use and modify this code for your own software 
# as long as you retain information about the original author
# in your code as shown below.
#
# <author>Jonathan Racicot</author>
# <email>infectedpacket@gmail.com</email>
# <date>2015-03-26</date>
# <url>https://github.com/infectedpacket</url>
#
__version_info__ = ('0','1','0')
__version__ = '.'.join(__version_info__)

import sys, traceback
import math
import time
import argparse
import collections
import datetime
from enum import Enum
from bitstring import BitArray


# =============================================================================
# Parameter information
class Params:
    parameters = {
      "debug" : {
            "cmd"       : "debug",
            "help"      : "Enables debug mode.",
            "choices"   : [True, False]
            },
      "vmfversion" : {
            "cmd"       : "vmfversion",
            "help"      :
                """Field representing the version of the MIL-STD-2045-47001 header being used for the message.""",
            "choices"   : ["std47001", "std47001b","std47001c","std47001d","std47001d_change"]
            },
      "compress" : {
            "cmd"       : "compress",
            "help"      :
                """This field represents whether the message or messages contained in the User Data portion of the Application PDU have been UNIX compressed or compressed using GZIP.""",
            "choices"   : ["unix", "gzip"]
            },
      "headersize" : {
            "cmd"       : "headersize",
            "help"      :
                """Indicates the size in octets of the header""",
            "choices"   : []
          },
      "originator_urn" : {
            "cmd"       : "originator_urn",
            "help"      : """24-bit code used to uniquely identify friendly military units, broadcast networks and multicast groups.""",
            "choices"   : []
          },
      "originator_unitname" : {
            "cmd"       : "originator_unitname",
            "help"      : """Specify the name of the unit sending the message.""",
            "choices"   : []
          },
      "rcpt_urns"       : {
            "cmd"       : "rcpt_urns",
            "help"      : """List of 24-bit codes used to uniquely identify friendly units.""",
            "choices"   : []
          },
      "rcpt_unitnames"       : {
            "cmd"       : "rcpt_unitnames",
            "help"      : """ List of variable size fields of character-coded identifiers for friendly units. """,
            "choices"   : []
          },
      "info_urns"       : {
            "cmd"       : "info_urns",
            "help"      : """List of 24-bit codes used to uniquely identify friendly units.""",
            "choices"   : []
          },
      "info_unitnames"       : {
            "cmd"       : "info_unitnames",
            "help"      : """ List of variable size fields of character-coded identifiers for friendly units. """,
            "choices"   : []
          },
      "umf"             : {
            "cmd"       : "umf",
            "choices"   : ["link16", "binary", "vmf", "nitfs", "rdm", "usmtf", "doi103", "xml-mtf", "xml-vmf"],
            "help"      : """ Indicates the format of the message contained in the user data field."""
          },
      "messagevers"     : {
            "cmd"       : "messagevers",
            "choices"   : [],
            "help"      : """Represents the version of the message standard contained in the user data field."""
            },
      "fad"             : {
            "cmd"       : "fad",
            "choices"   : ["netcon", "geninfo", "firesp", "airops", "intops", "landops","marops", "css", "specialops", "jtfopsctl", "airdef"],
            "help"      : "Identifies the functional area of a specific VMF message using code words."
            },
      "msgnumber"       : {
            "cmd"       : "msgnumber",
            "choices"   : [],
            "help"      : """Represents the number that identifies a specific VMF message within a functional area."""
            },
      "msgsubtype"      : {
            "cmd"       : "msgsubtype",
            "choices"   : [],
            "help"      : """Represents a specific case within a VMF message, which depends on the UMF, FAD and message number."""
            },
      "filename"        : {
            "cmd"       : "filename",
            "choices"   : [],
            "help"      : """Indicates the name of the computer file or data block contained  in the User Data portion of the application PDU."""
            },
      "msgsize"         : {
            "cmd"       : "msgsize",
            "choices"   : [],
            "help"      : """Indicates the size(in bytes) of the associated message within the User Data field."""
            },
      "opind"           : {
            "cmd"       : "opind",
            "choices"   : ["op", "ex", "sim", "test"],
            "help"      : "Indicates the operational function of the message."
            },
      "retransmission"  : {
            "cmd"       : "retransmission",
            "choices"   : [True, False],
            "help"      : """Indicates whether a message is a retransmission."""
            },
      "msgprecedence"   : {
            "cmd"       : "msgprecedence",
            "choices"   : ["reserved", "critic", "flashover", "flash", "imm", "pri", "routine"],
            "help"      : """Indicates relative precedence of a message."""
            },
      "classification"  : {
            "cmd"       : "classification",
            "choices"   : ["unclass", "conf", "secret", "topsecret"],
            "help"      : """Security classification of the message."""
            },
      "releasemark"     : {
            "cmd"       : "releasemark",
            "choices"   : [],
            "help"      : """Support the exchange of a list of up to 16 country codes with which the message can be release."""
            },
      "originatordtg"   : {
            "cmd"       : "originatordtg",
            "choices"   : [],
            "help"      : """ Contains the date and time in Zulu Time that the message was prepared."""
            },
      "perishdtg"   : {
            "cmd"       : "perishdtg",
            "choices"   : [],
            "help"      : """Provides the latest time the message is still of value."""
            },
      "ackmachine"      : {
            "cmd"       : "ackmachine",
            "choices"   : [True, False],
            "help"      : """Indicates whether the originator of a machine requires a machine acknowledgement for the message."""
            },
      "ackop"           : {
            "cmd"       : "ackop",
            "choices"   : [True, False],
            "help"      : """Indicates whether the originator of the message requires an acknowledgement for the message from the recipient."""
            },
      "reply"           : {
            "cmd"       : "reply",
            "choices"   : [True, False],
            "help"      : """Indicates whether the originator of the message requires an operator reply to the message."""
            }
    }


usage = "%(prog)s [options] data"
parser = argparse.ArgumentParser(usage=usage,
    prog="vmfcat",
    version="%(prog)s "+__version__,
    description="Allows crafting of Variable Message Format (VMF) messages.")

io_options = parser.add_argument_group(
    "Input/Output Options", "Types of I/O supported.")
io_options.add_argument("-d", "--debug",
    dest=Params.parameters['debug']['cmd'],
    action="store_true",
    help=Params.parameters['debug']['help'])
io_options.add_argument("-i", "--interactive",
    dest="interactive",
    action="store_true",
    help="Create and send VMF messages interactively.")
io_options.add_argument("-of", "--ofile",
    dest="outputfile",
    nargs="?",
    type=argparse.FileType('w'),
        default=sys.stdout,
        help="File to output the results. STDOUT by default.")

# =============================================================================
# Application Header Arguments
header_options = parser.add_argument_group(
    "Application Header", "Flags and Fields of the application header.")
header_options.add_argument("--vmf-version",
    dest=Params.parameters["vmfversion"]["cmd"],
    action="store",
    choices=Params.parameters["vmfversion"]["choices"],
        default="std47001c",
        help=Params.parameters["vmfversion"]["help"])
header_options.add_argument("--compress",
    dest=Params.parameters["compress"]["cmd"],
    action="store",
    choices=Params.parameters["compress"]["choices"],
    help=Params.parameters["compress"]["help"])
header_options.add_argument("--header-size",
    dest=Params.parameters["headersize"]["cmd"],
    action="store",
    type=int,
    help=Params.parameters["headersize"]["help"])

# =============================================================================
# Originator Address Group Arguments
orig_addr_options = parser.add_argument_group(
    "Originator Address Group", "Fields of the originator address group.")
orig_addr_options.add_argument("--orig-urn",
    dest=Params.parameters["originator_urn"]["cmd"],
    metavar="URN",
    type=int,
    action="store",
    help=Params.parameters["originator_urn"]["help"])
orig_addr_options.add_argument("--orig-unit",
    dest=Params.parameters["originator_unitname"]["cmd"],
    metavar="STRING",
    action="store",
    help=Params.parameters["originator_unitname"]["help"])
# =============================================================================

# =============================================================================
# Recipient Address Group Arguments
recp_addr_options = parser.add_argument_group(
    "Recipient Address Group", "Fields of the recipient address group.")
recp_addr_options.add_argument("--rcpt-urns",
    nargs="+",
    dest=Params.parameters['rcpt_urns']['cmd'],
    metavar="URNs",
    help=Params.parameters['rcpt_urns']['help'])
recp_addr_options.add_argument("--rcpt-unitnames",
    nargs="+",
    dest=Params.parameters['rcpt_unitnames']['cmd'],
    metavar="UNITNAMES",
    help=Params.parameters['rcpt_unitnames']['help'])
# =============================================================================

# =============================================================================
# Information Address Group Arguments
info_addr_options = parser.add_argument_group(
    "Information Address Group", "Fields of the information address group.")
info_addr_options.add_argument("--info-urns",
    dest=Params.parameters["info_urns"]["cmd"],
    metavar="URNs",
    nargs="+",
    action="store",
    help=Params.parameters["info_urns"]["help"])
info_addr_options.add_argument("--info-units",
    dest="info_unitnames",
    metavar="UNITNAMES",
    action="store",
    help="Specify the name of the unit of the reference message.")
# =============================================================================

# =============================================================================
# Message Handling Group Arguments
msg_handling_options = parser.add_argument_group(
    "Message Handling Group", "Fields of the message handling group.")
msg_handling_options.add_argument("--umf",
    dest=Params.parameters["umf"]["cmd"],
    action="store",
    choices=Params.parameters["umf"]["choices"],
    help=Params.parameters["umf"]["help"])
msg_handling_options.add_argument("--msg-version",
    dest=Params.parameters["messagevers"]["cmd"],
    action="store",
    metavar="VERSION",
    type=int,
    help=Params.parameters["messagevers"]["help"])
msg_handling_options.add_argument("--fad",
    dest=Params.parameters["fad"]["cmd"],
    action="store",
    choices=Params.parameters["fad"]["choices"],
    help=Params.parameters["fad"]["help"])
msg_handling_options.add_argument("--msg-number",
    dest=Params.parameters["msgnumber"]["cmd"],
    action="store",
    type=int,
    metavar="1-127",
    help=Params.parameters["msgnumber"]["help"])
msg_handling_options.add_argument("--msg-subtype",
    dest=Params.parameters["msgsubtype"]["cmd"],
    action="store",
    type=int,
    metavar="1-127",
    help=Params.parameters["msgsubtype"]["help"])
msg_handling_options.add_argument("--filename",
    dest=Params.parameters["filename"]["cmd"],
    action="store",
    help=Params.parameters["filename"]["help"])
msg_handling_options.add_argument("--msg-size",
    dest=Params.parameters["msgsize"]["cmd"],
    action="store",
    type=int,
    metavar="SIZE",
    help=Params.parameters["msgsize"]["help"])

msg_handling_options.add_argument("--opind",
    dest=Params.parameters["opind"]["cmd"],
    action="store",
    choices=Params.parameters["opind"]["choices"],
    help=Params.parameters["opind"]["help"])

msg_handling_options.add_argument("--retrans",
    dest=Params.parameters["retransmission"]["cmd"],
    action="store_true",
    help=Params.parameters["retransmission"]["help"])

msg_handling_options.add_argument("--msg-prec",
    dest=Params.parameters["msgprecedence"]["cmd"],
    action="store",
    choices=Params.parameters["msgprecedence"]["choices"],
    help=Params.parameters["msgprecedence"]["help"])

msg_handling_options.add_argument("--class",
    dest=Params.parameters["classification"]["cmd"],
    action="store",
    nargs="+",
    choices=Params.parameters["classification"]["cmd"],
    help=Params.parameters["classification"]["cmd"])

msg_handling_options.add_argument("--release",
    dest=Params.parameters["releasemark"]["cmd"],
    action="store",
    metavar="COUNTRIES",
    help=Params.parameters["releasemark"]["help"])

msg_handling_options.add_argument("--orig-dtg",
    dest=Params.parameters["originatordtg"]["cmd"],
    action="store",
    metavar="YYYY-MM-DD HH:mm[:ss] [extension]",
    help=Params.parameters["originatordtg"]["cmd"])
msg_handling_options.add_argument("--perish-dtg",
    dest=Params.parameters["perishdtg"]["cmd"],
    action="store",
    metavar="YYYY-MM-DD HH:mm[:ss]",
    help=Params.parameters["perishdtg"]["cmd"])

# =====================================================================================

# =====================================================================================
# Acknowledge Request Group Arguments
ack_options = parser.add_argument_group(
    "Acknowledgement Request Group", "Options to request acknowledgement and replies.")
ack_options.add_argument("--ack-machine",
    dest=Params.parameters["ackmachine"]["cmd"],
    action="store_true",
    help=Params.parameters["ackmachine"]["help"])
ack_options.add_argument("--ack-op",
     dest=Params.parameters["ackop"]["cmd"],
    action="store_true",
    help=Params.parameters["ackop"]["help"])
ack_options.add_argument("--reply",
    dest=Params.parameters["reply"]["cmd"],
    action="store_true",
    help=Params.parameters["reply"]["help"])
# =====================================================================================

# =====================================================================================
# Response Data Group Arguments
#
resp_options = parser.add_argument_group(
    "Response Data Options", "Fields for the response data group.")
resp_options.add_argument("--ack-dtg", 
    dest="ackdtg", 
    action="store", 
    metavar="YYYY-MM-DD HH:mm[:ss] [extension]", 
    help=
    """
        Provides the date and time of the original message that
         is being acknowledged.
    """)
resp_options.add_argument("--rc",
    dest="rccode",
    action="store",
    choices=[
        "mr", "cantpro", "oprack",
        "wilco", "havco", "cantco", "undef"],
    help=
    """
        Codeword representing the Receipt/Compliance answer to the
        acknowledgement request.
    """)
resp_options.add_argument("--cantpro",
    dest="cantpro",
    action="store",
    type=int,
    metavar="1-32",
    help=
    """
        Indicates the reason that a particular message cannot be
        processed by a recipient or information address.
    """)
resp_options.add_argument("--cantco", 
    dest="cantco", 
    action="store", 
    choices=[
        "comm", "ammo", "pers", 
        "fuel", "env", "equip", "tac", "other"],
    help=
    """
        Indicates the reason that a particular recipient cannot 
        comply with a particular message.
    """)
resp_options.add_argument("--reply-amp", 
    dest="replyamp", 
    action="store",
    help=
    """
        Provide textual data an amplification of the recipient's
        reply to a message.
    """)

# =====================================================================================


# =====================================================================================
# Reference Message Data Group Arguments
#
ref_msg_options = parser.add_argument_group(
    "Reference Message Data Group", "Fields of the reference message data group.")
ref_msg_options.add_argument("--ref-urn",
    dest="ref_urn",
    metavar="URN",
    action="store",
    help="Specify the URN of the reference message.")
ref_msg_options.add_argument("--ref-unit", 
    dest="ref_unitname", 
    metavar="STRING",
    action="store", 
    help="Specify the name of the unit of the reference message.")
ref_msg_options.add_argument("--ref-dtg", 
    dest="refdtg", 
    action="store", 
    metavar="YYYY-MM-DD HH:mm[:ss] [extension]", 
    help="Date time group of the reference message.")
# =====================================================================================


# =====================================================================================
# Message Security Data Group Arguments
#
msg_sec_grp = parser.add_argument_group(
    "Message Security Group", "Fields of the message security group.")
msg_sec_grp.add_argument("--sec-param", 
    dest="secparam", 
    action="store", 
    choices=[
        'auth', 'undef'
    ],
    help=
    """
        Indicate the identities of the parameters and algorithms that enable
        security processing.
    """)
msg_sec_grp.add_argument("--keymat-len", 
    dest="keymatlen", 
    action="store", 
    type=int,
    help="Defines the size in octets of the Keying Material ID field.") 
msg_sec_grp.add_argument("--keymat-id", 
    dest="keymatid", 
    action="store", 
    type=int,
    help="Identifies the key which was used for encryption.")
msg_sec_grp.add_argument("--crypto-init-len", 
    dest="crypto_init_len", 
    action="store", 
    type=int,
    help=
    """
        Defines the size, in 64-bit blocks, of the Crypto 
        Initialization field.
    """)
msg_sec_grp.add_argument("--crypto-init", 
    dest="crypto_init", 
    action="store", 
    type=int,
    help=
    """
        Sequence of bits used by the originator and recipient to 
        initialize the encryption/decryption process.
    """)
msg_sec_grp.add_argument("--keytok-len", 
    dest="keytok_len", 
    action="store", 
    type=int,
    help="Defines the size, in 64-bit blocks, of the Key Token field.")
msg_sec_grp.add_argument("--keytok", 
    dest="keytok", 
    action="store", 
    type=int,
    help=
    """
        Contains information enabling each member of each address
         group to decrypt the user data associated with this message 
        header.
    """)
msg_sec_grp.add_argument("--autha-len", 
    dest="autha-len", 
    action="store", 
    type=int, 
    metavar="LENGTH",
    help=
    """
        Defines the size, in 64-bit blocks, of the Authentification 
        Data (A) field.
    """)
msg_sec_grp.add_argument("--authb-len",
    dest="authb-len",
    action="store",
    type=int,
    metavar="LENGTH",
    help=
    """
        Defines the size, in 64-bit blocks, of the Authentification 
        Data (B) field.
    """)
msg_sec_grp.add_argument("--autha", 
    dest="autha", 
    action="store", 
    type=int,
    help=
    """
        Data created by the originator to provide both connectionless 
        integrity and data origin authentication (A).
    """)
msg_sec_grp.add_argument("--authb", 
    dest="authb", 
    action="store", 
    type=int,
    help=
    """
        Data created by the originator to provide both connectionless 
        integrity and data origin authentication (B).
    """)
msg_sec_grp.add_argument("--ack-signed", 
    dest="acksigned", 
    action="store_true", 
    help=
    """
        Indicates whether the originator of a message requires a signed
         response from the recipient.
    """)
msg_sec_grp.add_argument("--pad-len",
    dest="pad_len",
    action="store", type=int,
    metavar="LENGTH",
    help=
    """
        Defines the size, in octets, of the message security 
        padding field.
    """)
msg_sec_grp.add_argument("--padding",
    dest="padding",
    action="store",
    type=int,
    help=
    """
        Necessary for a block encryption algorithm so the content
        of the message is a multiple of the encryption block length.
    """)
# =============================================================================




# =============================================================================
# Global Variables

ENABLE_FUTURE_GRP = 0

ABSENT  = 0x0
PRESENT = 0x1

DEFAULT_FPI = ABSENT
DEFAULT_FRI = 0
DEFAULT_GPI = ABSENT
DEFAULT_GRI = 0

TERMINATOR = 0x7E

CODE_GRP_HEADER     = "header"
CODE_GRP_ORIGIN_ADDR    = "G1"
CODE_GRP_RCPT_ADDR  = "G2"
CODE_GRP_INFO_ADDR  = "G3"
CODE_GRP_MSG_HAND   = "R3"
CODE_GRP_VMF_MSG_IDENT  = "G9"
CODE_GRP_ORIGIN_DTG = "G10"
CODE_GRP_PERISH_DTG = "G11"
CODE_GRP_ACK        = "G12"
CODE_GRP_RESPONSE   = "G13"
CODE_GRP_REF        = "G14"
CODE_GRP_MSG_SECURITY   = "G20"
CODE_GRP_KEYMAT     = "G21"
CODE_GRP_CRYPTO_INIT    = "G22"
CODE_GRP_KEY_TOKEN  = "G23"
CODE_GRP_AUTH_A     = "G24"
CODE_GRP_AUTH_B     = "G25"
CODE_GRP_SEC_PAD    = "G26"

NO_STATEMENT        = 63

MSG_SUCCESS     = 0x0
MSG_ERROR   = 0x1
MSG_WARN    = 0x2
MSG_INFO    = 0x3
MSG_INFO    = 0x4

CMD_SAVE = 'save'
CMD_LOAD = 'load'
CMD_SET = 'set'
CMD_SHOW = 'show'
CMD_HEADER = 'header'
CMD_HELP = 'help'
CMD_QUIT = 'quit'

# =============================================================================



# =============================================================================
# VMF Version Enumeration Class
#
# Description: 
#   Enumerates the different versions of the VMF protocol.
#
class version(Enum):
    std47001  = 0x0
    std47001b = 0x1
    std47001c = 0x2
    std47001d = 0x3
    std47001d_change = 0x4
    undefined1 = 0x5
    undefined2 = 0x6
    undefined3 = 0x7
    undefined4 = 0x8
    undefined5 = 0x9
    undefined6 = 0xa
    undefined7 = 0xb
    undefined8 = 0xc
    undefined9 = 0xd
    undefined10 = 0xe
    not_implemented = 0xf
# =============================================================================

# =============================================================================
# Data Compression Types Enumeration Class
#
# Description: 
#   Enumerates the different data compression methods
#   supported by the VMF protocol.
#
class data_compression(Enum):
    unix = 0x0
    gzip = 0x1
    undefined1 = 0x2
    undefined2 = 0x3
# =============================================================================

# =============================================================================
# Uniform Message Format (UMF) Enumeration Class
#
# Description: 
#
class umf(Enum):
    link16 = 0x0
    binary = 0x1
    vmf = 0x2
    nitfs = 0x3
    rdm = 0x4
    usmtf = 0x5
    doi103 = 0x6
    xml_mtf = 0x7
    xml_vmf = 0x8
    undefined1 = 0x9
    undefined2 = 0xA
    undefined3 = 0xB
    undefined4 = 0xC
    undefined5 = 0xD
    undefined6 = 0xE
    undefined7 = 0xF    
# =============================================================================

class operation(Enum):
    operation = 0x0
    exercise = 0x1
    simulation = 0x2
    test = 0x3
    
class precedence(Enum):
    reserved1 = 0x7
    reserved2 = 0x6
    critic = 0x5
    flash_override = 0x4
    flash = 0x3
    immediate = 0x2
    priority = 0x1
    routine = 0x0
    
class classification(Enum):
    unclassified = 0x0
    confidential = 0x1
    secret = 0x2
    top_secret = 0x3

class rc_codes(Enum):
    undefined0 = 0x0
    machine_receipt = 0x1
    cantpro = 0x2
    oprack = 0x3
    wilco = 0x4
    havco = 0x5
    cantco = 0x6
    undefined7 = 0x7

class fad_codes(Enum):
    netcon = 0x0
    geninfo = 0x1
    firesp = 0x2
    airops = 0x3
    intops = 0x4
    landops = 0x5
    marops = 0x6
    css = 0x7
    specialops = 0x8
    jtfopsctl = 0x9
    airdef = 0xA
    undefined1 = 0xB
    undefined2 = 0xC
    undefined3 = 0XD
    undefined4 = 0xE
    undefined5 = 0xF


class cantco_reasons(Enum):
    comms = 0x0
    ammo = 0x1
    pers = 0x2
    fuel = 0x3
    env = 0x4
    equip = 0x5
    tactical = 0x6
    other = 0x7

class cantpro_reasons(Enum):
    undefned = 0x00
    field_content = 0x01
    msg_routing = 0x02
    address = 0x03
    ref_point = 0x04
    fire_units = 0x05
    mission_ctrl = 0x06
    mission_num = 0x07
    target_num = 0x08
    schd_num = 0x09
    ctrl_addr = 0x0A
    track_num = 0x0B
    invalid = 0x0C
    msg_conv = 0x0D
    file_full = 0x0E
    unrec_msg_num = 0x0F
    corelate_file = 0x10
    limit_exceed = 0x11
    sys_inactive = 0x12
    addr_unk = 0x13
    cant_fwd_acy = 0x14
    cant_fwd_lnk = 0x15
    ill_jux_fields = 0x16
    fail_uncompress_lzw = 0x17
    fail_uncompress_lz77 = 0x18
    too_old = 0x19
    sec_restrict = 0x1A
    auth_fail = 0x1B
    crt_404 = 0x1C
    crt_invalid = 0x1D
    spi_unsupported = 0x1E
    fail_signed_ack = 0x1F
    no_retrans = 0x20

# =============================================================================
# Group Class
#
# Description:
#   Class to represent sets of fields with similar functions.
#
class group(object):
    is_root = False
    is_repeatable = False
    max_repeat = 1
    name = ""
    parent_group = None
    index = 0

    def __init__(self, _name, _is_repeatable=False, _isroot=False, _parent=None, _max_repeat=1, _index=0):
        self.name = _name
        self.is_root = _isroot
        self.is_repeatable = _is_repeatable
        self.max_repeat = _max_repeat
        self.parent_group = _parent
        self.index = _index
        self.fields = []#*(6+15*ENABLE_FUTURE_GRP)
        self.gpi = DEFAULT_FPI
        self.gri = DEFAULT_GRI

    def __repr__(self):
        return "{:d}:{:s}".format(self.index, self.name)

    def __cmp__(self, _field):
        if (isinstance(_field, field)):
            return self.index.__cmp__(_field.index)
        elif (isinstance(_field, group)):
            return self.index.__cmp__(_field.index)
        else:
            raise Exception("Provided comparision item must be an integer.")

    def enable(self):
        self.gpi = PRESENT

    def set_gri(self, _value):
        self.gri = _value

    def append_field(self, _field):
        #TODO toggle GPI if field is indicator or FPI ==- present
        #doesn't work...
        if (_field.fpi == PRESENT):
            self.gpi = PRESENT
        self.fields.append(_field)

    def get_bit_array(self):
        b = BitArray()
        b.append("{:#03b}".format(self.gpi))
        if (self.gpi == ABSENT):
            return b
        if (self.is_repeatable):
            b.append("{:#03b}".format(self.gri))
        for f in self.fields:
            fbits = f.get_bit_array()
            b.append(fbits)
        return b
# =============================================================================
# Field Class
# Contains common properties to VMF fields 
class field(object):
    fpi = DEFAULT_FPI
    fri = DEFAULT_FRI
    is_repeatable = False
    is_indicator = False
    size = 0
    name = ""
    value = 0
    format_str = ""
    grp_code = ""
    enumerator = None
    index = 0

    def __init__(self, _name, _size, _value=0, _groupcode = 0, _repeatable=False, _indicator=False, _enumerator=None, _index=0):
        self.name = _name
        self.size = _size
        self.value = _value
        self.grp_code = _groupcode
        self.is_repeatable = _repeatable
        self.is_indicator = _indicator
        self.enumerator = _enumerator
        self.index = _index
        self.format_str = "{:#0" + str(self.size+2) + "b}"

    def __repr__(self):
        return "<Field: {:d}:{:s}:{:s}>".format(self.index, self.name, str(self.value))

    def __cmp__(self, _field):
        if (isinstance(_field, field)):
            return self.index.__cmp__(_field.index)
        elif (isinstance(_field, group)):
            return self.index.__cmp__(_field.index)
        else:
            raise Exception("Provided comparision item must be an integer.")
    
    def enable_and_set(self, _value):
        self.fpi = PRESENT
        self.value = _value

    def get_bit_array(self):
        b = BitArray()
        if (self.is_indicator):
            # This check is to verify the version number, which is
            # an exception. It is not an indicator, but it does not
            # have a FPI.
            field_value = self.value
            if (self.name == "Version" and self.enumerator):
                field_value = factory.get_value_from_dict(self.value, self.enumerator)
                b.append(self.format_str.format(field_value))
            else:   
                b.append("{:#03b}".format(field_value))
            return b

        b.append("{:#03b}".format(self.fpi))
        if (self.fpi == PRESENT):
            field_value = self.value
            if (self.enumerator):
                field_value = factory.get_value_from_dict(self.value, self.enumerator)
            if (isinstance(field_value, int)):
                if (self.is_repeatable):
                    b.append("{:#03b}".format(self.fri))
                if (self.fpi == PRESENT or self.is_indicator):
                    b.append(self.format_str.format(field_value))
        return b
        #else:
            #TODO: Process strings

# =============================================================================

# =============================================================================
# Datetime Group (DTG) Field Class
# Represents a field containing a DTG value. 
class dtg_field(field):
    has_extension = False
        
    def __init__(self, _name, _size=46, _value=0, _groupcode = 0, _repeatable=False, _extension=True, _index=0):
        super(dtg_field, self).__init__(_name, _size, _value, _groupcode, _repeatable, _index)
        self.has_extension=_extension
        self.fields = {
            "year"  : field(
                    _name="year", 
                    _size=7, 
                    _indicator=True,
                    _index=0),
            "month" : field(
                    _name="month", 
                    _size=4, 
                    _indicator=True,
                    _index=1),
            "day"   : field(
                    _name="day", 
                    _size=5, 
                    _indicator=True,
                    _index=2),
            "hour"  : field(
                    _name="hour", 
                    _size=5, 
                    _indicator=True,
                    _index=3),
            "minute": field(
                    _name="minute", 
                    _size=6, 
                    _indicator=True,
                    _index=4),
            "second": field(
                    _name="second", 
                    _size=6, 
                    _value=NO_STATEMENT,
                    _indicator=True,
                    _index=5),
            "ext"   : field(
                    _name="extension",
                    _size=12,
                    _index=6)
        }
        self.enable_and_set(_value)

    def enable_and_set(self, _value):
        #Expected format: YYYY-MM-DD HH:mm[:ss] [extension]"
        self.value = _value
        if (_value):
            self.fpi = PRESENT
            date_items = _value.split(' ')

            if (len(date_items) == 2 or len(date_items) == 3):
                format_str = "%Y-%m-%d %H:%M"
                #
                # Check if seconds are included.
                #
                secondsIncluded = False
                if (date_items[1].count(":") > 1):
                    format_str = "%Y-%m-%d %H:%M:%S"
                    secondsIncluded = True
                else:
                    self.fields["second"].enable_and_set(NO_STATEMENT)
                #TODO: the year should only contain the last 2 digits, not the entire
                # 4 digits.
                date_obj = datetime.datetime.strptime(date_items[0] + ' ' + date_items[1], format_str)
                self.fields["year"].enable_and_set(date_obj.year)
                print(self.fields["year"])
                self.fields["month"].enable_and_set(date_obj.month)
                self.fields["day"].enable_and_set(date_obj.day)
                self.fields["hour"].enable_and_set(date_obj.hour)
                self.fields["minute"].enable_and_set(date_obj.minute)
                if (secondsIncluded):
                    self.fields["second"].enable_and_set(date_obj.second)
                #               
                # Check if extension has been included
                #
                if (len(date_items) == 3):
                    self.fields["ext"].enable_and_set(date_items[2])
                print(self)
            else:
                raise Exception("Unknown datetime group format: {:s}.".format(_value))

        #else:
        #   raise Exception("Datetime group provided is null or empty.")
        
    def get_bit_array(self):
        b = BitArray()
        dtgfields = self.fields.values()
        #self.fields.sort()
        dtgfields.sort()
        for f in dtgfields:
            if (f.name == "ext"):
                if (self.has_extension):
                    fbits = f.get_bit_array()
                    b.append(fbits)
            else:
                fbits = f.get_bit_array()
                b.append(fbits)
        return b

    def __repr__(self):
        return "<Datetime Group Field: {:d}:{:s}:{:s}>".format(self.index, self.name, str(self.value))
        
# =============================================================================


# =============================================================================
# Factory Class
#
# Description: Defines the fields required to build a VMF message and
#       creates those fields based on user-provides values via
#       the command line.
#
class factory:

    vmf_fields = {
        "vmfversion"        : [field(
                        _name="Version",
                        _size=4,
                        _enumerator=version,
                        _groupcode=CODE_GRP_HEADER,
                        _indicator=True,
                        _index=0)],
        "compress"      : [field(
                        _name="Data Compression",
                        _size=2,
                        _enumerator=data_compression,
                        _groupcode=CODE_GRP_HEADER,
                        _index=1)],
        "originator_urn"    : [field(
                        _name="Originator URN",
                        _size=24, 
                        _groupcode=CODE_GRP_ORIGIN_ADDR,
                        _index=0)],
        "originator_unitname"   : [field(
                        _name="Originator Unit Name", 
                        _size=448, 
                        _groupcode=CODE_GRP_ORIGIN_ADDR,
                        _index=0)],
        "rcpt_urns"     : [field(
                        _name="Recipient URN", 
                        _size=24, 
                        _groupcode=CODE_GRP_RCPT_ADDR,
                        _index=0)],
        "rcpt_unitnames"    : [field(
                        _name="Recipient Unit Name", 
                        _size=448, 
                        _groupcode=CODE_GRP_RCPT_ADDR,
                        _index=0)],
        "info_urns"     : [field(
                        _name="Information URN", 
                        _size=24, 
                        _groupcode=CODE_GRP_INFO_ADDR,
                        _index=0)],
        "info_unitnames"    : [field(
                        _name="Information Unit Name", 
                        _size=448, 
                        _groupcode=CODE_GRP_INFO_ADDR,
                        _index=0)],
        "umf"           : [field(
                        _name="UMF", 
                        _size=4, 
                        _enumerator=umf,
                        _groupcode=CODE_GRP_MSG_HAND,
                        _index=0)],
        "messagevers"       : [field(
                        _name="Message Standard Version", 
                        _size=4, 
                        _groupcode=CODE_GRP_MSG_HAND,
                        _index=1)],
        "fad"           : [field(
                        _name="FAD", 
                        _size=4,
                        _enumerator=fad_codes, 
                        _groupcode=CODE_GRP_VMF_MSG_IDENT,
                        _index=0)],
        "msgnumber"     : [field(
                        _name="Message Number",
                        _size=7,
                        _groupcode=CODE_GRP_VMF_MSG_IDENT,
                        _index=1)],
        "msgsubtype"        : [field(
                        _name="Message Subtype",
                        _size=7,
                        _groupcode=CODE_GRP_VMF_MSG_IDENT,
                        _index=2)],
        "filename"      : [field(
                        _name="File name",
                        _size=448,
                        _groupcode=CODE_GRP_MSG_HAND,
                        _index=3)],
        "msgsize"       : [field(
                        _name="Message Size",
                        _size=20,
                        _groupcode=CODE_GRP_MSG_HAND,
                        _index=4)],
        "opind"         : [field(
                        _name="Operation Indicator",
                        _size=2,
                        _groupcode=CODE_GRP_MSG_HAND,
                        _index=5)],
        "retransmission"    : [field(
                        _name="Retransmit Indicator",
                        _size=1,
                        _groupcode=CODE_GRP_MSG_HAND,
                        _index=6)],
        "msgprecedence"     : [field(
                        _name="Message Precedence Code",
                        _size=3,
                        _enumerator=precedence,
                        _groupcode=CODE_GRP_MSG_HAND,
                        _index=7)],
        "classification"    : [field(
                        _name="Security Classification",
                        _size=2,
                        _enumerator=classification,
                        _groupcode=CODE_GRP_MSG_HAND,
                        _index=8)],
        "releasemark"       : [field(
                        _name="Control/Release Marking",
                        _size=9,
                        _repeatable=True,
                        _groupcode=CODE_GRP_MSG_HAND,
                        _index=9)],
        "originatordtg"     : [dtg_field(
                        _name="Originator DTG",
                        _groupcode=CODE_GRP_ORIGIN_DTG,
                        _index=10)],
        "perishdtg"     : [dtg_field(
                        _name="Perishability DTG",
                        _groupcode=CODE_GRP_PERISH_DTG,
                        _extension=False,
                        _index=11)],
        "ackmachine"    : [field(
                        _name="Machine Acknowledge",
                        _size=1,
                        _groupcode=CODE_GRP_ACK,
                        _indicator=True,
                        _index=1)],
        "ackop"         : [field(
                        _name="Operator Acknowledge",
                        _size=1,
                        _groupcode=CODE_GRP_ACK,
                        _indicator=True,
                        _index=2)],
        "reply"         : [field(
                        _name="Operator Reply Request",
                        _size=1,
                        _groupcode=CODE_GRP_ACK,
                        _indicator=True,
                        _index=3)],
        "ackdtg"        : [dtg_field(
                        _name="DTG of Ack'd Msg.",
                        _groupcode=CODE_GRP_RESPONSE,
                        _index=12)],
        "rccode"        : [field(
                        _name="R/C",
                        _size=3,
                        _enumerator=rc_codes,
                        _groupcode=CODE_GRP_RESPONSE,
                        _indicator=True,
                        _index=13)],
        "cantco"        : [field(
                        _name="Cantco Reason Code",
                        _size=3,
                        _enumerator=cantco_reasons,
                        _groupcode=CODE_GRP_RESPONSE,
                        _index=14)],
        "cantpro"       : [field(
                        _name="Cantpro Reason Code",
                        _size=6,
                        _enumerator=cantpro_reasons,
                        _groupcode=CODE_GRP_RESPONSE,
                        _index=15)],
        "replyamp"      : [field(
                        _name="Reply Amplification",
                        _size=350,
                        _groupcode=CODE_GRP_RESPONSE,
                        _index=16)],
        "ref_urn"       : [field(
                        _name="Reference Message URN",
                        _size=24,
                        _groupcode=CODE_GRP_REF,
                        _index=0)],
        "ref_unitname"      : [field(
                        _name="Reference Message Unit Name",
                        _size=448,
                        _groupcode=CODE_GRP_REF,
                        _index=0)],
        "refdtg"        : [dtg_field(
                        _name="Reference Message DTG",
                        _groupcode=CODE_GRP_REF,
                        _index=1)],
        "secparam"      : [field(
                        _name="Security Parameters",
                        _size=4,
                        _groupcode=CODE_GRP_MSG_SECURITY,
                        _indicator=True,
                        _index=0)],
        "keymatlen"     : [field(
                        _name="Keying Material Id Length",
                        _size=3,
                        _groupcode=CODE_GRP_KEYMAT,
                        _indicator=True,
                        _index=0)],
        "keymatid"      : [field(
                        _name="Keying Material Id",
                        _size=64,
                        _groupcode=CODE_GRP_KEYMAT,
                        _indicator=True,
                        _index=1)],
        "crypto_init_len"   : [field(
                        _name="Crypto Initialization Length",
                        _size=4,
                        _groupcode=CODE_GRP_CRYPTO_INIT,
                        _indicator=True,
                        _index=0)],
        "crypto_init"       : [field(
                        _name="Crypto Initialization",
                        _size=1024,
                        _groupcode=CODE_GRP_CRYPTO_INIT,
                        _indicator=True,
                        _index=1)],
        "keytok_len"        : [field(
                        _name="Key Token Length",
                        _size=8,
                        _groupcode=CODE_GRP_KEY_TOKEN,
                        _indicator=True,
                        _index=0)],
        "keytok"        : [field(
                        _name="Key Token",
                        _size=16384,
                        _groupcode=CODE_GRP_KEY_TOKEN,
                        _indicator=True,
                        _repeatable=True,
                        _index=1)],
        "autha_len"     : [field(
                        _name="Auth. Data Length (A)",
                        _size=7,
                        _groupcode=CODE_GRP_AUTH_A,
                        _indicator=True,
                        _index=0)],
        "autha"         : [field(
                        _name="Auth Data (A)",
                        _size=8192,
                        _groupcode=CODE_GRP_AUTH_A,
                        _indicator=True,
                        _index=1)],
        "authb_len"     : [field(
                        _name="Auth. Data Length (B)",
                        _size=7,
                        _groupcode=CODE_GRP_AUTH_B,
                        _indicator=True,
                        _index=0)],
        "authb"         : [field(
                        _name="Auth Data (B)",
                        _size=8192,
                        _groupcode=CODE_GRP_AUTH_B,
                        _indicator=True,
                        _index=1)],
        "acksigned"     : [field(
                        _name="Signed Acknowledge Indicator",
                        _size=1,
                        _groupcode=CODE_GRP_MSG_SECURITY,
                        _indicator=True,
                        _index=6)],
        "pad_len"       : [field(
                        _name="Message Security Padding Length",
                        _size=8,
                        _groupcode=CODE_GRP_SEC_PAD,
                        _indicator=True,
                        _index=0)],
        "padding"       : [field(
                        _name="Message Security Padding",
                        _size=2040,
                        _groupcode=CODE_GRP_SEC_PAD,
                        _index=1)]

    }

    vmf_groups = {
        CODE_GRP_HEADER     : [group(
                        _name="Application Header",
                        _isroot=True)],
        CODE_GRP_ORIGIN_ADDR    : [group(
                        _name="Originator Address",
                        _parent=CODE_GRP_HEADER,
                        _index=2)],
        CODE_GRP_RCPT_ADDR  : [group(
                        _name="Recipient Address Group",
                        _is_repeatable=True,
                        _max_repeat=16,
                        _parent=CODE_GRP_HEADER,
                        _index=3)],
        CODE_GRP_INFO_ADDR  : [group(
                        _name="Information Address Group",
                        _is_repeatable=True,
                        _max_repeat=16,
                        _parent=CODE_GRP_HEADER,
                        _index=4)],
        CODE_GRP_MSG_HAND   : [group(
                        _name="Message Handling Group",
                        _is_repeatable=True,
                        _max_repeat=16,
                        _parent=CODE_GRP_HEADER,
                        _index=5+5*ENABLE_FUTURE_GRP)],

        CODE_GRP_VMF_MSG_IDENT  : [group(
                        _name="VMF Message Identification",
                        _parent=CODE_GRP_MSG_HAND,
                        _index=2)],
        CODE_GRP_ORIGIN_DTG : [group(
                        _name="Originator DTG",
                        _parent=CODE_GRP_MSG_HAND,
                        _index=10)],
        CODE_GRP_PERISH_DTG : [group(
                        _name="Perishability DTG",
                        _parent=CODE_GRP_MSG_HAND,
                        _index=11)],
        CODE_GRP_ACK        : [group(
                        _name="Acknowledgement Req. Group",
                        _parent=CODE_GRP_MSG_HAND,
                        _index=12)],
        CODE_GRP_RESPONSE   : [group(
                        _name="Response Data Group",
                        _parent=CODE_GRP_MSG_HAND,
                        _index=13)],
        CODE_GRP_REF        : [group(
                        _name="Reference Message Data Group",
                        _is_repeatable=True,
                        _max_repeat=4,
                        _parent=CODE_GRP_MSG_HAND,
                        _index=14)],
        CODE_GRP_MSG_SECURITY   : [group(
                        _name="Message Security Group",
                        _parent=CODE_GRP_MSG_HAND,
                        _index=15+5*ENABLE_FUTURE_GRP)],
        CODE_GRP_KEYMAT     : [group(
                        _name="Keying Material Group",
                        _parent=CODE_GRP_MSG_SECURITY,
                        _index=1)],
        CODE_GRP_CRYPTO_INIT    : [group(
                        _name="Crypto. Initialization Group",
                        _parent=CODE_GRP_MSG_SECURITY,
                        _index=2)],
        CODE_GRP_KEY_TOKEN  : [group(
                        _name="Key Token Group",
                        _parent=CODE_GRP_MSG_SECURITY,
                        _index=3)],
        CODE_GRP_AUTH_A     : [group(
                        _name="Authentication Group (A)",
                        _parent=CODE_GRP_MSG_SECURITY,
                        _index=4)],
        CODE_GRP_AUTH_B     : [group(
                        _name="Authentication Group (B)",
                        _parent=CODE_GRP_MSG_SECURITY,
                        _index=5)],
        CODE_GRP_SEC_PAD    : [group(
                        _name="Message Security Padding",
                        _parent=CODE_GRP_MSG_SECURITY,
                        _index=7)]

    }

    def __init__(self, _args):
        print_msg(MSG_INFO, "Building VMF factory...")
        for field_name, field_value in _args.__dict__.items():
            if (field_value != None and field_name in self.vmf_fields.keys()):
                vmf_field_name = self.vmf_fields[field_name][0].name
                if (isinstance(field_value, list)):
                    template = self.vmf_fields[field_name][0]
                    nb_items = len(field_value)
                    self.vmf_fields[field_name] = [template]*nb_items
                    for field_idx in range(0, len(self.vmf_fields[field_name])):
                        self.vmf_fields[field_name][field_idx].enable_and_set(field_value[field_idx])

                        if (isinstance(field_value[field_idx], int)):
                            print_setting(1, vmf_field_name, "0x{:02x}".format(field_value[field_idx]))
                        else:
                            print_setting(1, vmf_field_name, "{:s}".format(field_value[field_idx]))

                else:
                    self.vmf_fields[field_name][0].enable_and_set(field_value)
                    if (isinstance(field_value, int)):
                        print_setting(1, vmf_field_name, "0x{:02x}".format(field_value))
                    else:
                        print_setting(1, vmf_field_name, "{:s}".format(field_value))


    @staticmethod
    def get_value_from_dict(_key, _dict):
        for key, value in _dict.__dict__.items():
            if (key.lower() == _key.lower()):
                return value
        return None

    def get_vmf_msg(self):
        print_msg(MSG_DEBUG, "Creating VMF message object...")
        print_msg(MSG_DEBUG, "Adding fields to groups...")
        for (f_name, f_array) in self.vmf_fields.iteritems():
            i = 0
            group_code = f_array[i].grp_code
            if (not group_code in self.vmf_groups):
                raise Exception("Undefined group code: {:s}.".format(group_code))
            group_name = self.vmf_groups[group_code][i].name
            self.vmf_groups[group_code][i].append_field(f_array[i])
            print_msg(MSG_DEBUG, "Added field '{:s}' to group '{:s}'.".format(f_array[i].name, group_name))
        print_msg(MSG_DEBUG, "Creating group structure...")
        root_grp = self.vmf_groups[CODE_GRP_HEADER]
        for (g_code, g_array) in self.vmf_groups.iteritems():
            i = 0
            parent_group = g_array[i].parent_group
            if (not parent_group is None):
                self.vmf_groups[parent_group][i].fields.append(g_array[i])
                print_msg(MSG_DEBUG, "Added '{:s}' child group to '{:s}'.".format(g_array[i].name, parent_group))
        return root_grp

    def print_structure(self):
        print("="*60)
        print_msg(MSG_DEBUG, "Printing VMF Message Structure")
        header = self.vmf_groups[CODE_GRP_HEADER][0]
        header.fields.sort()
        print_msg(MSG_SUCCESS, "\t{:s}".format(header.name))
        for i in range(0, len(header.fields)):
            header_field = header.fields[i]
            if (isinstance(header_field, field)):
                print_msg(MSG_ERROR, "\t      {:s}".format(header_field.name))
            elif (isinstance(header_field, group)):
                self.print_struct_rec(3, header_field)
            else:
                raise Exception("Unknown header element type: {:s}.".format(header_field))

    def print_struct_rec(self, _tabs, _elem):
        if (isinstance(_elem, field)):
            print_msg(MSG_ERROR, "\t   " + " "*_tabs + "{:s}".format(_elem.name))
        elif(isinstance(_elem, group)):
            print_msg(MSG_SUCCESS, "\t   " + " "*_tabs + "{:s}".format(_elem.name))
            _elem.fields.sort()
            for f in _elem.fields:
                self.print_struct_rec(_tabs+4, f)
        else:
            raise Exception("Unknown element type: {:s}.".format(_elem))

    def print_header_binary(self):
        print("="*60)
        print_msg(MSG_INFO, "VMF Message Binary Fields")
        header = self.vmf_groups[CODE_GRP_HEADER][0]
        for i in range(0, len(header.fields)):
            f = header.fields[i]
            ba = f.get_bit_array()
            if (isinstance(f, field)):
                print_setting(1, f.name, ba.bin)
            elif(isinstance(f, group)):
                print_setting(1, f.name, ba.bin[0])
                self.print_header_binary_rec(1, f)

    def print_header_binary_rec(self, _tabs, _elem):
        for i in range(0, len(_elem.fields)):
            f = _elem.fields[i]
            if (isinstance(f, field)):
                ba = f.get_bit_array()
                print_setting(_tabs, f.name, ba.bin)
            elif(isinstance(f, group)):
                ba = f.get_bit_array()
                print_setting(1, f.name, ba.bin[0])
                self.print_header_binary_rec(_tabs, f)

    @staticmethod
    def string_to_bitarray(_string, _maxsize=448):
        b = BitArray()
        pos = 0
        if (_string):
            for c in _string:
                c_str = "{:#09b}".format(ord(c))
                b.insert(c_str, pos)
                pos += 7
        if (len(b.bin) < _maxsize):
            b.insert(TERMINATOR, pos)
        if (len(b.bin) > _maxsize):
            raise ("Size of bit array exceeds the maximum size allowed ({:d}).".format(_maxsize))
        return b

def banner():
    print("Copyright (C) 2015  Jonathan Racicot <jonathan.racicot@rmc.ca>")
    print(
    """
    This program comes with ABSOLUTELY NO WARRANTY. This is
    free software, and you are welcome to redistribute it
    under certain conditions.
    """)


def print_msg(_type, _msg):
    if (_type == MSG_ERROR):
        exc_type, exc_obj, exc_tb = sys.exc_info()
        if (exc_tb):
            print("[-] " + _msg + "[{:d}]".format(exc_tb.tb_lineno))
        else:
            print("[-] " + _msg )

    elif (_type == MSG_WARN):
        print("[!] " + _msg)
    elif (_type == MSG_INFO):
        print("[*] " + _msg)
    elif (_type == MSG_DEBUG):
        print("[>] " + _msg)
    elif (_type == MSG_SUCCESS):
        print("[+] " + _msg)
    else:
        print("    " + _msg)


def print_setting(_prefixtabs, _setting, _value):
    linesize = 59
    setting_len = len(_setting)
    value_len = len(_value)
    tabs_len = 3+4*_prefixtabs

    if (setting_len + value_len + tabs_len >= linesize):
        indent = 3
        line1 = ('\t' * _prefixtabs) + _setting
        print_msg(MSG_SUCCESS, line1)
        lines_len = int(math.ceil(value_len / (linesize-tabs_len-indent)))
        cut_start = 0
        cut_end = 0
        for i in range(0, lines_len):
            prefix = ('\t' * _prefixtabs) + (' ' * indent)
            cut_end = cut_start+linesize - (len(prefix)+3)
            substr = _value[cut_start:cut_end]
            print_msg(-1, prefix + substr)
            cut_start = cut_end + 1
    else:
        space_len = linesize - value_len - (tabs_len + setting_len)
        line = ('\t' * _prefixtabs) + _setting + (' ' * space_len) + _value
        print_msg(MSG_SUCCESS, line)


def main(args):
    try:

        if (args.interactive):
            cmd = ""
            while (cmd.lower() != CMD_QUIT):
                sys.stdout.write("<<< ")
                user_input = sys.stdin.readline()
                tokens = user_input.rstrip().split()
                cmd = tokens[0]
                if (cmd.lower() == CMD_SET):
			if (len(tokens) != 3):
				print_msg(MSG_ERROR, "Usage: set <field> <value>")
			else:
			       param = tokens[1]
			       value = tokens[2]
			       if (param in Params.__dict__.keys()):
				   Params.__dict__[param] = value
				   new_value = Params.__dict__[param]
				   print_msg(MSG_SUCCESS, "{:s} = {:s}".format(param, new_value))
			       else:
				   print_msg(MSG_ERROR, "Unknown parameter {:s}.".format(param))
                elif (cmd.lower() == CMD_SHOW):
                       param = tokens[1]
                       if (param in Params.parameters.keys()):
                           value = Params.__dict__[param]
                           if (isinstance(value, int)):
                               value = "0x{:02x}".format(value)
                           print_msg(MSG_INFO, "{:s} = {:s}".format(param, value))
                       else:
                            print_msg(MSG_ERROR, "Unknown command {:s}.".format(param))

                elif (cmd.lower() == CMD_HEADER):
		    vmf_factory = factory(args)
		    print("="*60)
		    app_header = vmf_factory.get_vmf_msg()
		    if (args.debug):
			vmf_factory.print_structure()
			vmf_factory.print_header_binary()
                elif (cmd.lower() == CMD_LOAD):
                       print_msg(MSG_INFO, "Not implemented")
                elif (cmd.lower() == CMD_SAVE):
                       print_msg(MSG_INFO, "Not implemented")
                elif (cmd.lower() == CMD_HELP):
			if (len(tokens) == 1):
				print_msg(MSG_INFO, "show <field>")
				print_msg(MSG_INFO, "set <field> <value>")
				print_msg(MSG_INFO, "header")
				print_msg(MSG_INFO, "help <field>")
				print_msg(MSG_INFO, "quit")
			else:
				param = tokens[1]
				if (param in Params.__dict__.keys()):
				    help_msg = Params.parameters[param]['help']
				    print_msg(MSG_INFO, help_msg)
				    if (len(Params.parameters[param]['choices']) > 0):
					choices_msg = str(Params.parameters[param]['choices'])
					print_msg(MSG_INFO, choices_msg)
				else:
				    print_msg(MSG_ERROR, "Unknown command {:s}.".format(cmd))
                elif (cmd.lower() == CMD_QUIT):
                    pass
                else:
                       print_msg(MSG_ERROR, "Unknown command {:s}.".format(cmd))
        else:
            vmf_factory = factory(args)
            # Testing below
            print("="*60)
            app_header = vmf_factory.get_vmf_msg()
            if (args.debug):
                vmf_factory.print_structure()
                vmf_factory.print_header_binary()
    except Exception as e:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback, file=sys.stdout)
        print_msg(MSG_ERROR, e.message)

if __name__ == "__main__":
    banner()
    main(parser.parse_args(namespace=Params))
