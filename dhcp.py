"""
# DHCP Library

Small DHCP library/framework to open a raw channel and send and recieve encoded and decoded DHCP Packets of the below
format:

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
+---------------+---------------+---------------+---------------+
|                            xid (4)                            |
+-------------------------------+-------------------------------+
|           secs (2)            |           flags (2)           |
+-------------------------------+-------------------------------+
|                          ciaddr  (4)                          |
+---------------------------------------------------------------+
|                          yiaddr  (4)                          |
+---------------------------------------------------------------+
|                          siaddr  (4)                          |
+---------------------------------------------------------------+
|                          giaddr  (4)                          |
+---------------------------------------------------------------+
|                                                               |
|                          chaddr  (16)                         |
|                                                               |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|                          sname   (64)                         |
+---------------------------------------------------------------+
|                                                               |
|                          file    (128)                        |
+---------------------------------------------------------------+
|                                                               |
|                          options (variable)                   |
+---------------------------------------------------------------+

See [RFC 2131](https://tools.ietf.org/html/rfc2131) for more information.
"""

# Python STDLIB
import struct
import random
import time
# Python 3rd Party Libraries
import pcapy
# Common
from common import hashobj, stdout, stderr
# Network Types
import network_types
# Networking
import networking

"""
# DHCP Flags

DHCP Flags indicating how a DHCP Response should be sent, ie: via unicast to the client or via broadcast in the case
where the DHCP client has no IP.
"""

flags = hashobj()

# Values

flags.UNICAST   = 0b0000000000000000
flags.BROADCAST = 0b1000000000000000

# Lookup Table

flags.lookup = {
    flags.UNICAST:   "unicast",
    flags.BROADCAST: "broadcast"
}

"""
# DHCP OPCODE

BOOTREQUEST from client to server and BOOTREPLY back.
"""

opcodes = hashobj()

# Values

opcodes.BOOT_REQUEST = 1
opcodes.BOOT_REPLY   = 2

# Lookup Table

opcodes.lookup = {
    opcodes.BOOT_REQUEST: "boot_request",
    opcodes.BOOT_REPLY:   "boot_reply"
}

"""
# DHCP Options

Contains option types, their ID, their name, size, encoding and description. See

- https://tools.ietf.org/html/rfc2132#section-2
- https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#options

for more information.
"""

options = hashobj()

# Values

options.SUBNET_MASK                             = 1
options.TIME_OFFSET                             = 2
options.ROUTER                                  = 3
options.TIME_SERVER                             = 4
options.NAME_SERVER                             = 5
options.DOMAIN_SERVER                           = 6
options.LOG_SERVER                              = 7
options.QUOTES_SERVER                           = 8
options.LPR_SERVER                              = 9
options.RLP_SERVER                              = 11
options.HOST_NAME                               = 12
options.BOOT_FILE_SIZE                          = 13
options.MERIT_DUMP_FILE                         = 14
options.DOMAIN_NAME                             = 15
options.SWAP_SERVER                             = 16
options.ROOT_PATH                               = 17
options.EXTENSIONS_FILE                         = 18
# IP Layer Per-Host Parameters
options.IP_FORWARDING_ENABLE_DISABLE            = 19
options.NON_LOCAL_SOURCE_ROUTING_ENABLE_DISABLE = 20
options.POLICY_FILTER                           = 21
options.MAXIMUM_DATAGRAM_REASSEMBLY_SIZE        = 22
options.DEFAULT_IP_TIME_TO_LIVE                 = 23
options.PATH_MTU_AGING_TIMEOUT                  = 24
options.PATH_MTU_PLATEAU_TABLE                  = 25
# IP Layer Per-Interface Parameters
options.INTERFACE_MTU                           = 26
options.ALL_SUBNETS_ARE_LOCAL                   = 27
options.BROADCAST_ADDRESS                       = 28
options.PERFORM_MASK_DISCOVERY                  = 29
options.MASK_SUPPLIER                           = 30
options.PERFORM_ROUTER_DISCOVERY                = 32
options.ROUTER_SOLICITATION_ADDRESS             = 32
options.STATIC_ROUTE                            = 33
# Link Layer Per-Interface Parameters
options.TRAILER_ENCAPSULATION                   = 34
options.ARP_CACHE_TIMEOUT                       = 35
options.ETHERNET_ENCAPSULATION                  = 36
# TCP Parameters
options.TCP_DEFAULT_TTL                         = 37
options.TCP_KEEPALIVE_INTERVAL                  = 38
options.TCP_KEEPALIVE_GARBAGE                   = 39
# Application and Service Parameters
options.NTP_SERVER                              = 42
options.SIMPLE_MAIL_TRANSPORT_PROTOCOL          = 69
options.POST_OFFICE_PROTOCOL_SERVER             = 70
options.DEFAULT_WORLD_WIDE_WEB_SERVER           = 72
options.DEFAULT_FINGER_SERVER                   = 73
options.DEFAULT_INTERNET_RELAY_CHAT_SERVER      = 74
options.RELAY_AGENT_INFORMATION                 = 82
# DHCP Extensions to BOOTP
options.REQUESTED_IP_ADDRESS                    = 50
options.IP_ADDRESS_LEASE_TIME                   = 51
options.OVERLOAD                                = 52
options.TFTP_SERVER_NAME                        = 66
options.BOOTFILE_NAME                           = 67
options.DHCP_MESSAGE_TYPE                       = 53
options.SERVER_IDENTIFIER                       = 54
options.PARAMETER_REQUEST_LIST                  = 55
options.MESSAGE                                 = 56
options.MAXIMUM_DHCP_MESSAGE_SIZE               = 57
options.RENEWAL_TIME_VALUE                      = 58
options.REBINDING_TIME_VALUE                    = 59
options.VENDOR_CLASS_IDENTIFIER                 = 60
options.CLIENT_IDENTIFIER                       = 61
options.TZ_POSIX_STRING                         = 100
options.TZ_DATABASE_STRING                      = 101
# End
options.END                                     = 255

# Lookup Table

options.lookup = {
    options.SUBNET_MASK:                             ("subnet_mask",                             4,    "ip",            "Network Mask for the client"                                                                                                                                                                 ),
    options.TIME_OFFSET:                             ("time_offset",                             4,    "uint32",        "Offset of the client subnet in seconds"                                                                                                                                                      ),
    options.ROUTER:                                  ("router",                                  None, "iplist",        "List of Routers IP Addresses listed in order of preference"                                                                                                                                  ),
    options.TIME_SERVER:                             ("time_server",                             None, "iplist",        "NTP Servers available to the client"                                                                                                                                                         ),
    options.NAME_SERVER:                             ("name_server",                             None, "iplist",        "Local Name Servers"                                                                                                                                                                          ),
    options.DOMAIN_SERVER:                           ("domain_server",                           None, "iplist",        "Available DNS Servers"                                                                                                                                                                       ),
    options.LOG_SERVER:                              ("log_server",                              None, "iplist",        "List of MIT-LCS UDP log servers available to the client in order of preference"                                                                                                              ),
    options.QUOTES_SERVER:                           ("quotes_server",                           None, "iplist",        "List of RFC 865 Cookie (Quote of the day) servers available to the client"                                                                                                                   ),
    options.LPR_SERVER:                              ("lpr_server",                              None, "iplist",        "List of Line Printer Daemon servers available to the client listed in order of preference"                                                                                                   ),
    options.RLP_SERVER:                              ("rlp_server",                              None, "iplist",        "List of Resource Location servers listed in order of preference"                                                                                                                             ),
    options.HOST_NAME:                               ("host_name",                               None, "cstring",       "Host name of the client (local host name)"                                                                                                                                                   ),
    options.BOOT_FILE_SIZE:                          ("boot_file_size",                          2,    "uint16",        "Default boot image of the client (BOOTP)"                                                                                                                                                    ),
    options.MERIT_DUMP_FILE:                         ("merit_dump_file",                         None, "cstring",       "Path name to the clients core image which should be dumped on crash"                                                                                                                         ),
    options.DOMAIN_NAME:                             ("domain_name",                             None, "cstring",       "Domain name the client should use when resolving hostnames via the DNS"                                                                                                                      ),
    options.SWAP_SERVER:                             ("swap_server",                             None, "iplist",        "IP Address of the clients swap server (server providing swap storage to a diskless workstation over the network)"                                                                            ),
    options.ROOT_PATH:                               ("root_path",                               None, "cstring",       "Path name to the clients root list"                                                                                                                                                          ),
    options.EXTENSIONS_FILE:                         ("extensions_file",                         None, "cstring",       "BootP extensions file available via Tftp"                                                                                                                                                    ),
    options.IP_FORWARDING_ENABLE_DISABLE:            ("ip_forwarding_enable_disable",            1,    "cbool",         "Tells client to configure its IP layer for packet forwarding"                                                                                                                                ),
    options.NON_LOCAL_SOURCE_ROUTING_ENABLE_DISABLE: ("non_local_source_routing_enable_disable", 1,    "cbool",         "Tells the client to configure its IP layer to allow forwarding of datagrams with non local source routes"                                                                                    ),
    options.POLICY_FILTER:                           ("policy_filter",                           None, "ippairs",       "Specifies policy filters for non local source routing (if next hop does not match the policy, discard)"                                                                                      ),
    options.MAXIMUM_DATAGRAM_REASSEMBLY_SIZE:        ("maximum_datagram_reassembly_size",        2,    "uint16",        "Specifies max size datagram the client should be prepared to reassemble"                                                                                                                     ),
    options.DEFAULT_IP_TIME_TO_LIVE:                 ("default_ip_time_to_live",                 1,    "uint8",         "Default ttl for outgoing packets"                                                                                                                                                            ),
    options.PATH_MTU_AGING_TIMEOUT:                  ("path_mtu_aging_timeout",                  4,    "uint32",        "Timeout used while ageing MTUs"                                                                                                                                                              ),
    options.PATH_MTU_PLATEAU_TABLE:                  ("path_mtu_plateau_table",                  None, None,            "Table of MTU sizes when performing path MTU discovery (see RFC 1191)"                                                                                                                        ),
    options.INTERFACE_MTU:                           ("interface_mtu",                           2,    "uint16",        "MTU to use on interface"                                                                                                                                                                     ),
    options.ALL_SUBNETS_ARE_LOCAL:                   ("all_subnets_are_local",                   1,    "cbool",         "Whether the client can assume all subnets use the same MTU as the subnet the client is directly connected to"                                                                                ),
    options.BROADCAST_ADDRESS:                       ("broadcast_address",                       4,    "ip",            "Client broadcast address"                                                                                                                                                                    ),
    options.PERFORM_MASK_DISCOVERY:                  ("perform_mask_discovery",                  1,    "cbool",         "Whether or not the client should perform a subnet mask discovery via ICMP"                                                                                                                   ),
    options.MASK_SUPPLIER:                           ("mask_supplier",                           1,    "cbool",         "Whether the client should respond to subnet mask requests via ICMP"                                                                                                                          ),
    options.PERFORM_ROUTER_DISCOVERY:                ("perform_router_discovery",                1,    "cbool",         "Whether the client should solicit routers using Router discovery mechanisms (see RFC 1256)"                                                                                                  ),
    options.ROUTER_SOLICITATION_ADDRESS:             ("router_solicitation_address",             4,    "ip",            "Whether the client should transmit Router Solicitation Requests"                                                                                                                             ),
    options.STATIC_ROUTE:                            ("static_route",                            None, "ippairs",       "List of static routes the client should install on its routing cache"                                                                                                                        ),
    options.TRAILER_ENCAPSULATION:                   ("trailer_encapsulation",                   1,    "cbool",         "Whether or not the client should negotiate the use of trailers (RFC 893) when using the ARP protocol"                                                                                        ),
    options.ARP_CACHE_TIMEOUT:                       ("arp_cache_timeout",                       4,    "uint32",        "The timeout in seconds for ARP cache entries. The time is specified as a 32-bit unsigned integer"                                                                                            ),
    options.ETHERNET_ENCAPSULATION:                  ("ethernet_encapsulation",                  1,    "cbool",         "Whether or not the client should use Ethernet Version 2 (RFC 894) or IEEE 802.3 (RFC 1042) encapsulation if the interface is an Ethernet."                                                   ),
    options.TCP_DEFAULT_TTL:                         ("tcp_default_ttl",                         1,    "cbool",         "The default TTL that the client should use when sending TCP segments"                                                                                                                        ),
    options.TCP_KEEPALIVE_INTERVAL:                  ("tcp_keepalive_interval",                  4,    "uint32",        "This option specifies the interval (in seconds) that the client TCP should wait before sending a keepalive message on a TCP connection. The time is specified as a 32-bit unsigned integer." ),
    options.TCP_KEEPALIVE_GARBAGE:                   ("tcp_keepalive_garbage",                   1,    "cbool",         "Whether or not the client should send TCP keepalive messages with a octet of garbage for compatibility with older implementations."                                                          ),
    options.NTP_SERVER:                              ("ntp_server",                              None, "iplist",        "A list of NTP servers available to the client in order of preference."                                                                                                                       ),
    options.SIMPLE_MAIL_TRANSPORT_PROTOCOL:          ("simple_mail_transport_protocol",          None, "iplist",        "A list of SMTP servers available to the client in order of preference."                                                                                                                      ),
    options.POST_OFFICE_PROTOCOL_SERVER:             ("post_office_protocol_server",             None, "iplist",        "A list of POP3 servers available to the client in order of preference."                                                                                                                      ),
    options.DEFAULT_WORLD_WIDE_WEB_SERVER:           ("default_world_wide_web_server",           None, "iplist",        "A list of WWW servers available to the client in order of preference."                                                                                                                       ),
    options.DEFAULT_FINGER_SERVER:                   ("default_finger_server",                   None, "iplist",        "A list of Finger servers available to the client in order of preference."                                                                                                                    ),
    options.DEFAULT_INTERNET_RELAY_CHAT_SERVER:      ("default_internet_relay_chat_server",      None, "iplist",        "A list of IRC servers available to the client in order of preference."                                                                                                                       ),
    options.RELAY_AGENT_INFORMATION:                 ("relay_agent_information",                 None, None,            "Relay Agent Information"                                                                                                                                                                     ),
    options.REQUESTED_IP_ADDRESS:                    ("requested_ip_address",                    4,    "ip",            "Client request (DHCP DISCOVER) specific requested IP address parameter"                                                                                                                      ),
    options.IP_ADDRESS_LEASE_TIME:                   ("ip_address_lease_time",                   4,    "uint32",        "Lease time for an IP address used in client requests (DHCP DISCOVER and DHCP REQUEST) and also in server replies for specifying lease time (DHCP OFFER)"                                     ),
    options.OVERLOAD:                                ("overload",                                1,    "cbool",         "Indicates DHCP 'sname' or 'file' fields are being overloaded to carry DHCP options"                                                                                                          ),
    options.TFTP_SERVER_NAME:                        ("tftp_server_name",                        None, "cstring",       "Used to indicate the TFTP server name when SNAME has been overloaded"                                                                                                                        ),
    options.BOOTFILE_NAME:                           ("bootfile_name",                           None, "cstring",       "Used to identify a bootfile when FILE field in the DHCP headers has been overloaded"                                                                                                         ),
    options.DHCP_MESSAGE_TYPE:                       ("dhcp_message_type",                       1,    "uint8",         "DHCP Message type"                                                                                                                                                                           ),
    options.SERVER_IDENTIFIER:                       ("server_identifier",                       4,    "ip",            "Used in DHCPOFFER and DHCPREQUEST (AND OPTIONALLY MAY BE INCLUDED IN DHCPACK and DHCPNACK) added by the server to distinguish lease offers. It is set to the IP of the selected server."     ),
    options.PARAMETER_REQUEST_LIST:                  ("parameter_request_list",                  None, "uint8list",     "Used by the client to request for specific configuration parameters"                                                                                                                         ),
    options.MESSAGE:                                 ("message",                                 None, "cstring",       "Used by servers to indicate errors in DHCPNACK or by clients in DHCPDECLINE to indicate the reason for declining the configuration"                                                          ),
    options.MAXIMUM_DHCP_MESSAGE_SIZE:               ("maximum_dhcp_message_size",               2,    "uint16",        "Indicates the max length DHCP message the client is willing to accept in DHCPDISCOVER and DHCPREQUEST"                                                                                       ),
    options.RENEWAL_TIME_VALUE:                      ("renewal_time_value",                      4,    "uint32",        "Time interval from address assignment till the client enters renewal state"                                                                                                                  ),
    options.REBINDING_TIME_VALUE:                    ("rebinding_time_value",                    4,    "uint32",        "Time interval from address assignment till the client enters rebinding state"                                                                                                                ),
    options.VENDOR_CLASS_IDENTIFIER:                 ("vendor_class_identifier",                 None, "cstring",       "Vendor type and configuration of a DHCP Client"                                                                                                                                              ),
    options.CLIENT_IDENTIFIER:                       ("client_identifier",                       None, "cstring",       "Unique identifier specified by the client, treated as opaque objects by the server and must be unique within the subnet"                                                                     ),
    options.TZ_POSIX_STRING:                         ("tz_posix_string",                         None, None,            "DHCP Timezone Option as defined in RFC 4833"                                                                                                                                                 ),
    options.TZ_DATABASE_STRING:                      ("tz_database_string",                      None, None,            "The Timezone database identifier"                                                                                                                                                            ),
    options.END:                                     ("end",                                     0,    None,            "Flanks the end of the DHCP Options"                                                                                                                                                          )
}

"""
# DHCP Message Types

Contains the DHCP Message Types, their code, their opcodes, whether their header IPs should be set or not (or the
expected value of these IPs) and the options that should be cumpulsarily set or never set with the message type.
"""

message_types = hashobj()

# Values

message_types.DISCOVER = 1
message_types.OFFER    = 2
message_types.REQUEST  = 3
message_types.DECLINE  = 4
message_types.ACK      = 5
message_types.NACK     = 6
message_types.RELEASE  = 7
message_types.INFORM   = 8

# Lookup Table

message_types.lookup = {
    message_types.DISCOVER: ("discover", opcodes.BOOT_REQUEST, False, False, False, False, {},                                                         {options.SERVER_IDENTIFIER}                                                                                                                                      ),
    message_types.OFFER:    ("offer",    opcodes.BOOT_REPLY,   False, True,  None,  None,  {options.IP_ADDRESS_LEASE_TIME, options.SERVER_IDENTIFIER}, {options.REQUESTED_IP_ADDRESS, options.PARAMETER_REQUEST_LIST, options.CLIENT_IDENTIFIER, options.MAXIMUM_DHCP_MESSAGE_SIZE}                                     ),
    message_types.REQUEST:  ("request",  opcodes.BOOT_REQUEST, None,  False, False, False, {},                                                         {}                                                                                                                                                               ),
    message_types.DECLINE:  ("decline",  opcodes.BOOT_REQUEST, False, False, False, False, {options.REQUESTED_IP_ADDRESS, options.SERVER_IDENTIFIER},  {options.IP_ADDRESS_LEASE_TIME, options.VENDOR_CLASS_IDENTIFIER, options.PARAMETER_REQUEST_LIST, options.MAXIMUM_DHCP_MESSAGE_SIZE}                              ),
    message_types.ACK:      ("ack",      opcodes.BOOT_REPLY,   None,  True,  None,  None,  {options.SERVER_IDENTIFIER},                                {options.REQUESTED_IP_ADDRESS, options.PARAMETER_REQUEST_LIST, options.CLIENT_IDENTIFIER, options.MAXIMUM_DHCP_MESSAGE_SIZE}                                     ),
    message_types.NACK:     ("nack",     opcodes.BOOT_REPLY,   False, False, False, None,  {options.SERVER_IDENTIFIER},                                {options.REQUESTED_IP_ADDRESS, options.IP_ADDRESS_LEASE_TIME, options.PARAMETER_REQUEST_LIST, options.MAXIMUM_DHCP_MESSAGE_SIZE}                                 ),
    message_types.RELEASE:  ("release",  opcodes.BOOT_REQUEST, True,  False, False, False, {options.SERVER_IDENTIFIER},                                {options.REQUESTED_IP_ADDRESS, options.IP_ADDRESS_LEASE_TIME, options.VENDOR_CLASS_IDENTIFIER, options.PARAMETER_REQUEST_LIST, options.MAXIMUM_DHCP_MESSAGE_SIZE}),
    message_types.INFORM:   ("inform",   opcodes.BOOT_REQUEST, True,  False, False, False, {},                                                         {options.IP_ADDRESS_LEASE_TIME, options.SERVER_IDENTIFIER}                                                                                                       )
}


class error(Exception):
    """
    Error Class for DHCP Errors
    """
    # Error Types
    OPEN_CHANNEL_BAD_INTERFACE         = 1
    SEND_NO_INTERFACE                  = 2
    SEND_NO_DHCP_INPUT_SOURCE          = 3
    SEND_NO_DHCP_INPUT_DEST            = 4
    SEND_INVALID_DHCP_INPUT_CIP        = 5
    SEND_INVALID_DHCP_INPUT_YIP        = 6
    SEND_INVALID_DHCP_INPUT_SIP        = 7
    SEND_INVALID_DHCP_INPUT_GIP        = 8
    SEND_MISSING_OPTIONS               = 9
    SEND_ILLEGAL_OPTIONS               = 10
    SEND_FAIL_ENCODE_OPTION            = 11
    SEND_OPTION_LEN_MISMATCH           = 12
    SEND_OVERLOAD_OPTION_NOT_SUPPORTED = 13
    SEND_FAIL                          = 14
    RECIEVE_FAIL_DECODE_OPTION         = 15
    RECIEVE_INVALID_DHCP_MTYPES        = 16

    def __init__(self, error_type, message_type, error_value1=None, error_value2=None):
        """
        Constructor
        """
        self.error_type = error_type
        self.message_type = message_type
        self.v1 = error_value1
        self.v2 = error_value2

    def __str__(self):
        """
        ToString
        """
        if self.error_type == error.OPEN_CHANNEL_BAD_INTERFACE:
            return "DHCP Open Channel provided invalid Raw Channel/Interface {0}, cannot Broadcast.".format(
                self.v1
            )
        elif self.error_type == error.SEND_NO_INTERFACE:
            return "DHCP Send {0} provided invalid Raw Channel/Interface, cannot Broadcast.".format(
                self.message_type
            )
        elif self.error_type == error.SEND_NO_DHCP_INPUT_SOURCE:
            return "DHCP Send {0} cannot determine and was not supplied the packet source.".format(
                self.message_type
            )
        elif self.error_type == error.SEND_NO_DHCP_INPUT_DEST:
            return "DHCP Send {0} cannot determine and was not supplied the packet destination.".format(
                self.message_type
            )
        elif self.error_type == error.SEND_INVALID_DHCP_INPUT_CIP:
            return "DHCP Send {0} provided invalid CIP, got {1}, expected {2}.".format(
                self.message_type,
                self.v1,
                self.v2
            )
        elif self.error_type == error.SEND_INVALID_DHCP_INPUT_YIP:
            return "DHCP Send {0} provided invalid YIP, got {1}, expected {2}.".format(
                self.message_type,
                self.v1,
                self.v2
            )
        elif self.error_type == error.SEND_INVALID_DHCP_INPUT_SIP:
            return "DHCP Send {0} provided invalid SIP, got {1}, expected {2}.".format(
                self.message_type,
                self.v1,
                self.v2
            )
        elif self.error_type == error.SEND_INVALID_DHCP_INPUT_GIP:
            return "DHCP Send {0} provided invalid GIP, got {1}, expected {2}.".format(
                self.message_type,
                self.v1,
                self.v2
            )
        elif self.error_type == error.SEND_MISSING_OPTIONS:
            return "DHCP Send {0} missing options {1}.".format(
                self.message_type,
                self.v1
            )
        elif self.error_type == error.SEND_ILLEGAL_OPTIONS:
            return "DHCP Send {0} illegal options {1}.".format(
                self.message_type,
                self.v1
            )
        elif self.error_type == error.SEND_FAIL_ENCODE_OPTION:
            return "DHCP Send {0} failed to encode option {1} value {2} as {3}, error : {4}.".format(
                self.message_type,
                self.v1[0],
                self.v1[1],
                self.v1[2],
                self.v2
            )
        elif self.error_type == error.SEND_OPTION_LEN_MISMATCH:
            return "DHCP Send {0} failed as option {1} with value {2} has len {3}, expected len {4}.".format(
                self.message_type,
                self.v1[0],
                self.v1[1],
                self.v2[0],
                self.v2[1]
            )
        elif self.error_type == error.SEND_OVERLOAD_OPTION_NOT_SUPPORTED:
            return "DHCP Send {0} overload option not supported.".format(
                self.message_type
            )
        elif self.error_type == error.SEND_FAIL:
            return "DHCP Send {0} failed because of {1}.".format(
                self.message_type,
                self.v1
            )
        elif self.error_type == error.RECIEVE_FAIL_DECODE_OPTION:
            return "DHCP Receive failed to decode option {0} value {1} as {2}, error : {3}.".format(
                self.v1[0],
                self.v1[1],
                self.v1[2],
                self.v2
            )
        elif self.error_type == error.RECIEVE_INVALID_DHCP_MTYPES:
            return "DHCP Receive failed because of invalid mtypes {0} with different opcodes.".format(
                self.v1
            )
        else:
            return "DHCP Generic Error"


def validate_ip(given_ip, expected_value):
    """
    Validates a given ip against its expected value

    - If the expected value is None, returns true
    - If the expected value is True, returns False if the given ip is 0.0.0.0, True otherwise
    - If the expected value is False, returns True if the given ip is 0.0.0.0, False otherwise
    - If the expected value is an IP, returns true if the values of given and expected match, False otherwise

    Parameters:
    given_ip (str): Given IP value
    expected_value (object): True, False, None or Expected IP value

    Returns:
    bool: whether the given ip is valid
    """
    if expected_value is not None:
        if expected_value is True:
            if given_ip == "0.0.0.0":
                return False
        elif expected_value is False:
            if given_ip != "0.0.0.0":
                return False
        else:
            if expected_value != given_ip:
                return False
    return True


# DHCP Server Port
SERVER_UDP_PORT = 67

# DHCP Client port
CLIENT_UDP_PORT = 68

# Magic Cookie that tells us that this BOOTP packet is a DHCP one
MAGIC_COOKIE = 0x63825363


def open_raw_client_channel(interface_name, duration):
    """
    Opens a raw UDP channel for a DHCP client

    Opens a raw UDP channel that can capture packets with source port 67 and dest port 68 (ideal for a DHCP client to
    capture server packets).

    Parameters:
    interface_name (str): Interface Name
    duration (int): Channel lifespan

    Returns:
    object: Raw Channel
    """
    if interface_name not in pcapy.findalldevs():
        raise error(error.OPEN_CHANNEL_BAD_INTERFACE, None, error_value1=interface_name)
    channel = pcapy.open_live(interface_name, 60000, 1, duration*1000)
    channel.setfilter("udp")
    channel.setfilter("dst port {0}".format(CLIENT_UDP_PORT))
    channel.setfilter("src port {0}".format(SERVER_UDP_PORT))
    return channel


def open_raw_server_channel(interface_name, duration):
    """
    Opens a raw UDP channel for a DHCP server

    Opens a raw UDP channel that can capture packets with source port 68 and dest port 67 (ideal for a DHCP server to
    capture client packets).

    Parameters:
    interface_name (str): Interface Name
    duration (int): Channel lifespan

    Returns:
    object: Raw Channel
    """
    if interface_name not in pcapy.findalldevs():
        raise error(error.OPEN_CHANNEL_BAD_INTERFACE, None, error_value1=interface_name)
    channel = pcapy.open_live(interface_name, 60000, 1, duration*1000)
    channel.setfilter("udp")
    channel.setfilter("dst port {0}".format(SERVER_UDP_PORT))
    channel.setfilter("src port {0}".format(CLIENT_UDP_PORT))
    return channel


def _validate_and_encode_option(message_type_name, option_type, option_value):
    """
    Encodes a DHCP Option to its network binary form

    Takes an Option Type and Value, and encodes it to its network binary form of 1 Byte for Type Code, 1 Byte for Value
    Length and the remainder for the encoded value.

    Parameters:
    option_type (int): Option Type Code
    option_value (object): Option Value

    Returns:
    bytes: buffer containing the option type code, the option length and the encoded option value
    """
    option_name, expected_option_value_len, option_parser, _ = options.lookup[option_type]
    # Encode the Option Value
    try:
        option_value = getattr(network_types.encoders, option_parser)(option_value)
    except Exception as err:
        stderr.writeline("Failed to encode DHCP option of type {0} : {1}".format(option_type, err))
    # Validate the Option Length
    if (expected_option_value_len is not None) and (expected_option_value_len != len(option_value)):
        raise error(
            error.SEND_FAIL_ENCODE_OPTION,
            message_type_name,
            (option_name, option_value),
            (len(option_value), expected_option_value_len)
        )
    return option_value


def _validate_and_decode_option(buffer):
    """
    Decodes a DHCP Option in its network binary form

    Decodes a DHCP Option from its network binary form, validates it, decodes the value and returns a tuple containing
    the Option type code, the Option Length and the Option Value.

    Parameters:
    buffer (bytes): binary buffer containing the option

    Returns:
    tuple(int, int, object): Tuple of Option Type Code, Binary Option Value Length and Decoded Option Value
    """
    option_type = struct.unpack("!B", buffer[0:1])[0]
    if option_type == options.END:
        return (option_type, len(buffer)-2, None)
    option_length = struct.unpack("!B", buffer[1:2])[0]
    if option_type not in options.lookup:
        return (option_type, option_length, None)
    option_name, expected_option_value_len, option_parser, _ = options.lookup[option_type]
    if (expected_option_value_len is not None) and (option_length != expected_option_value_len):
        return (option_type, option_length, None)
    if len(buffer) < (option_length + 2):
        return (option_type, option_length, None)
    if option_parser is None:
        return (option_type, option_length, buffer[2:2+option_length])
    else:
        try:
            option_value = getattr(network_types.decoders, option_parser)(buffer[2:2+option_length])
        except Exception as err:
            stderr.writeline("failed to decode DHCP option of type {0} : {1}".format(option_name, err))
        return (option_type, option_length, option_value)


def send(mtype, hops, htype, xid, secs, dhcp_flags, chaddr, raw_channel, cip="0.0.0.0", yip="0.0.0.0", sip="0.0.0.0",
         gip="0.0.0.0", sname="", source_haddr=None, dest_haddr=None, source_ip=None, dest_ip=None, dhcp_options={},
         nicname=""):
    """
    Sends a DHCP Message with the given parameters

    Validates the given parameters and assembles them into a DHCP message and sends it out on the raw channel.

    Throws error on bad input.

    Parameters:
    mtype (int): DHCP Message type code
    hops (int): DHCP Message hops
    htype (int): DHCP Client ARP Hardware Type
    xid (int): DHCP Transaction ID specified by the Client
    secs (int): Seconds elapsed from DHCP Client Bootup
    dhcp_flags (int): DHCP Flags (broadcast or unicast)
    chaddr (str): Colon Seperated Hex formatted DHCP Client Hardware Address
    raw_channel (pcap): Raw channel on which to send DHCP messages
    cip (str): DHCP Client IP, defaults to 0.0.0.0
    yip (str): DHCP Your IP, defaults to 0.0.0.0
    sip (str): DHCP Server IP set for BOOTREPLY messages, defaults to 0.0.0.0
    gip (str): DHCP Gateway IP, used for relay with a Relay Agent, defaults to 0.0.0.0
    source_haddr (str): Colon Seperated Hex formatted DHCP Source Hardware Address, will default to chaddr for
        BOOTREQUEST messages
    dest_haddr (str): Colon Seperated Hex formatted DHCP Source Hardware Address, will default to chaddr for
        BOOTREPLY messages
    source_ip (str): DHCP Packet Source IP, defaults to 0.0.0.0 for broadcast BOOTREQUEST messages
    dest_ip (str): DHCP Packet Destination IP, defaults to 255.255.255.255 for broadcast BOOTREQUEST messages
    dhcp_options (dict): DHCP Options in the form of DHCP Message Code : DHCP Message Value
    """
    # Get the Message Type Details
    mtype_name, expected_opcode, expected_cip, expected_yip, expected_sip, expected_gip, cumpulsory_options, \
        cumpulsory_nonoptions = message_types.lookup[mtype]
    # Set some defaults based on flags and opcode
    if expected_opcode is opcodes.BOOT_REQUEST:
        source_haddr = chaddr
        source_port = CLIENT_UDP_PORT
        dest_port = SERVER_UDP_PORT
        if (not source_ip) and (cip != "0.0.0.0"):
            source_ip = cip
        if (not dest_ip) and (options.SERVER_IDENTIFIER in dhcp_options):
            dest_ip = dhcp_options[options.SERVER_IDENTIFIER]
    else:
        dest_haddr = chaddr
        source_port = SERVER_UDP_PORT
        dest_port = CLIENT_UDP_PORT
        if (not source_ip) and (options.SERVER_IDENTIFIER in dhcp_options):
            source_ip = dhcp_options[options.SERVER_IDENTIFIER]
        if (not dest_ip) and (yip != "0.0.0.0"):
            dest_ip = yip
    if dhcp_flags == flags.BROADCAST:
        dest_haddr = "ff:ff:ff:ff:ff:ff"
        source_ip = "0.0.0.0"
        dest_ip = "255.255.255.255"
    # Validate the parameters
    if raw_channel is None:
        raise error(error.SEND_NO_INTERFACE, mtype_name)
    if (not source_haddr) or (not source_ip):
        raise error(error.SEND_NO_DHCP_INPUT_SOURCE, mtype_name)
    if (not dest_haddr) or (not dest_ip):
        raise error(error.SEND_NO_DHCP_INPUT_SOURCE, mtype_name)
    if not validate_ip(cip, expected_cip):
        raise error(error.SEND_INVALID_DHCP_INPUT_CIP, mtype_name, cip, expected_cip)
    if not validate_ip(yip, expected_yip):
        raise error(error.SEND_INVALID_DHCP_INPUT_YIP, mtype_name, yip, expected_yip)
    if not validate_ip(sip, expected_sip):
        raise error(error.SEND_INVALID_DHCP_INPUT_SIP, mtype_name, sip, expected_sip)
    if not validate_ip(gip, expected_gip):
        raise error(error.SEND_INVALID_DHCP_INPUT_GIP, mtype_name, gip, expected_gip)
    missing_options = cumpulsory_options - dhcp_options.keys()
    illegal_options = cumpulsory_nonoptions & dhcp_options.keys()
    if missing_options:
        raise error(error.SEND_MISSING_OPTIONS, mtype_name, missing_options)
    if illegal_options:
        raise error(error.SEND_ILLEGAL_OPTIONS, mtype_name, illegal_options)
    if options.OVERLOAD in dhcp_options.keys():
        raise error(error.SEND_OVERLOAD_OPTION_NOT_SUPPORTED, mtype_name)
    # Encode the parameters as required
    _, hlen = networking.htypes.lookup[htype]
    cip = network_types.encoders.ip(cip)
    yip = network_types.encoders.ip(yip)
    sip = network_types.encoders.ip(sip)
    gip = network_types.encoders.ip(gip)
    # Assemble the DHCP Header
    buffer = b""
    buffer += struct.pack("!BBBB", expected_opcode, htype, hlen, hops)                          # 4 bytes
    buffer += struct.pack("!I", xid)                                                            # 4 bytes
    buffer += struct.pack("!HH", secs, dhcp_flags)                                              # 4 bytes
    buffer += cip                                                                               # 4 bytes
    buffer += yip                                                                               # 4 bytes
    buffer += sip                                                                               # 4 bytes
    buffer += gip                                                                               # 4 bytes
    buffer += struct.pack("!6sHQ", network_types.encoders.ethermac(chaddr), 0, 0)               # 16 bytes
    buffer += struct.pack("!64s", sname.encode("ascii"))                                        # 64 bytes
    buffer += struct.pack("!QQQQQQQQQQQQQQQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)  # 128 bytes
    buffer += struct.pack("!I", MAGIC_COOKIE)                                              # 4 bytes
    # Assemble the DHCP Options and Truncate
    buffer += struct.pack("!BBB", options.DHCP_MESSAGE_TYPE, options.lookup[options.DHCP_MESSAGE_TYPE][1], mtype)
    for option_type, option_value in dhcp_options.items():
        option_value = _validate_and_encode_option(mtype_name, option_type, option_value)
        buffer += struct.pack("!BB", option_type, len(option_value))
        buffer += option_value
    buffer += struct.pack("!B", options.END)
    # Pad upto at least 548 bytes
    if len(buffer) < 548:
        for i in range(0, 548 - len(buffer)):
            buffer += struct.pack("!B", 0)
    # Send the buffer in a UDP datagram
    identification = int(random.random() * 65535) & 0xffff
    segment = networking.udp.encapsulate(source_ip, dest_ip, source_port, dest_port, buffer)
    packet = networking.ipv4.encapsulate(source_ip, dest_ip, identification, segment)
    frame = networking.ethernet.encapsulate(source_haddr, dest_haddr, packet)
    try:
        send_message = {
            "message_type": mtype,
            "source_ip":    source_ip,
            "dest_ip":      dest_ip,
            "cip":          cip,
            "yip":          yip,
            "sip":          sip,
            "gip":          gip,
            "options":      dhcp_options,
            "sname":        sname,
            "shaddr":       source_haddr
        }
        stdout.writeline("sending dhcp {0} message to {1}:{2} on nic {3}".format(
            mtype_name, dest_ip, dest_port, nicname))
        stdout.write_named_dict(mtype_name, send_message)
        raw_channel.sendpacket(frame)
    except Exception as e:
        raise error(error.SEND_FAIL, mtype_name, e)


# Generator Function to Listen for DHCP Messages
def receive(mtypes, expected_chaddr, expected_xid, raw_channel, end_time, expected_dest_haddr=None,
            expected_dest_ip="0.0.0.0", expected_server_identifier=None, nicname=""):
    """
    Receive DHCP Messages from a raw socket channel

    Generator to receive and validate DHCP messages of the given message types with the expected chaddr and xid
    from the raw channel within the endtime. Can also filter by destination ip and MAC as well as the server ID.

    Parameters:
    mtypes (list): List of Message Types to accept. They must be of the same OPCODE
    expected_chaddr (str): Expected Client Hardware Address in the message in its colon seperated hex form
    expected_xid (int): Expected transaction ID of the message
    raw_channel (pcap): Raw channel on which to recieve
    end_time (int): Time from epoch at which to stop yielding
    expected_dest_haddr (str): Expected Destination Hardware Address of the message in its colon seperated hex \
        form, will also accept broadcast MAC
    expected_dest_ip (str): Expected Destination IP, will also accept broadcast messages
    expected_server_identifier: Expected value in the server identifier option (server ip). Defaults to None/0

    Returns:
    Generator[dict]: Generator that yields response offers
    """
    stdout.writeline("receiving Messages of type {0}".format([message_types.lookup[mtype][0].upper() for mtype in mtypes]))
    # Check that the Messages all have the same logical OPCODE
    expected_opcode = set(message_types.lookup[mtype][1] for mtype in mtypes)
    if len(expected_opcode) != 1:
        raise error(error.RECIEVE_INVALID_DHCP_MTYPES, None, mtypes)
    expected_opcode = expected_opcode.pop()
    # For BOOTREPLIES, the expected chaddr and the destination MAC of replies are the same
    if (expected_opcode == opcodes.BOOT_REPLY) and (not expected_dest_haddr):
        expected_dest_haddr = expected_chaddr
    # Within the timeframe, fetch packets
    while(int(time.time()) < end_time):
        try:
            _, frame = raw_channel.next()
            # Check Packet Length before unpacking DHCP
            if len(frame) < 282:
                # Frame too small to contain DHCP Headers
                continue
            # Unpack the Ethernet Frame
            dest_haddr, source_haddr, _, packet = networking.ethernet.unpack(frame)
            if (dest_haddr != "ff:ff:ff:ff:ff:ff") and expected_dest_haddr and \
                    (dest_haddr != expected_dest_haddr.lower()):
                # Packet not for us
                stderr.writeline("skipping recv BOOTP packet : unexpected dest mac {0}, expected {1}".format(
                    dest_haddr,
                    expected_dest_haddr
                ))
                continue
            # Unpack the IPv4 Packet
            _, _, _, source_ip, dest_ip, segment = networking.ipv4.unpack(packet)
            if (dest_ip != "255.255.255.255") and (expected_dest_ip != "0.0.0.0") and (dest_ip != expected_dest_ip):
                # Packet not for us
                stderr.writeline("skipping recv BOOTP packet : unexpected dest ip {0}, expected {1}".format(
                    dest_ip,
                    expected_dest_ip
                ))
                continue
            # Unpack the UDP Datagram
            source_port, dest_port, data = networking.udp.unpack(source_ip, dest_ip, segment)
            # Unpack the DHCP Data
            opcode, _, _, _, xid, _, _, cip, yip, sip, gip, chaddr, _, sname, _, magic_cookie = \
                struct.unpack("!BBBBIHH4s4s4s4s6s10s64s128sI", data[:240])
            # Validate that this BOOTP packet is DHCP
            if magic_cookie != MAGIC_COOKIE:
                stderr.writeline("skipping recv BOOTP packet : not DHCP")
                continue
            # Validate that the packet is destined to us
            if opcode == opcodes.BOOT_REPLY:
                if chaddr != network_types.encoders.ethermac(expected_chaddr):
                    stderr.writeline("skipping recv BOOTP packet : unexpected chaddr {0}, expected {1}".format(
                        chaddr,
                        expected_chaddr
                    ))
                    continue
                if xid != expected_xid:
                    stderr.writeline("skipping recv BOOTP packet : unexpected xid {0}, expected {1}".format(
                        xid,
                        expected_xid
                    ))
                    continue
            # Decode the options
            options_buffer = data[240:]
            dhcp_options = {}
            while options_buffer:
                (option_type, option_length, option_value) = _validate_and_decode_option(options_buffer)
                options_buffer = options_buffer[option_length+2:]
                if option_value:
                    dhcp_options[option_type] = option_value
            # Parse and Validate the Message Type Option
            if options.DHCP_MESSAGE_TYPE not in dhcp_options:
                stderr.writeline("skipping recv BOOTP packet : no message type in options")
                continue
            mtype = dhcp_options[options.DHCP_MESSAGE_TYPE]
            if mtype not in mtypes:
                stderr.writeline("skipping recv BOOTP packet : unwanted message type {0}".format(message_types.lookup[mtype][0]))
                continue
            # Get the Message defaults
            mtype_name, _, expected_cip, expected_yip, expected_sip, expected_gip, cumpulsory_options, cumpulsory_nonoptions = \
                message_types.lookup[mtype]
            # Validate OpCode
            if opcode != expected_opcode:
                stderr.writeline("skipping recv BOOTP packet : unexpected opcode {0}, expected {1}".format(
                    opcode,
                    expected_opcode
                ))
                continue
            # Decode the DHCP Address fields
            chaddr = network_types.decoders.ethermac(chaddr)
            cip = network_types.decoders.ip(cip)
            yip = network_types.decoders.ip(yip)
            sip = network_types.decoders.ip(sip)
            gip = network_types.decoders.ip(gip)
            # Validate the DHCP IP fields
            if not validate_ip(cip, expected_cip):
                stderr.writeline("skipping recv BOOTP packet : invalid cip {0}, expected {1}".format(
                    cip,
                    expected_cip
                ))
                continue
            if not validate_ip(yip, expected_yip):
                stderr.writeline("skipping recv BOOTP packet : invalid yip {0}, expected {1}".format(
                    yip,
                    expected_yip
                ))
                continue
            if not validate_ip(sip, expected_sip):
                stderr.writeline("skipping recv BOOTP packet : invalid sip {0}, expected {1}".format(
                    sip,
                    expected_sip
                ))
                continue
            if not validate_ip(gip, expected_gip):
                stderr.writeline("skipping recv BOOTP packet : invalid gip {0}, expected {1}".format(
                    gip,
                    expected_gip
                ))
                continue
            # Validate the Options
            missing_options = cumpulsory_options - dhcp_options.keys()
            illegal_options = cumpulsory_nonoptions & dhcp_options.keys()
            if missing_options:
                stderr.writeline("skipping recv BOOTP packet : missing options {0}".format(missing_options))
                continue
            if illegal_options:
                stderr.writeline("skipping recv BOOTP packet : illegal options {0}".format(illegal_options))
                continue
            # Validate the Server Identifier
            if (opcode == opcodes.BOOT_REPLY) and expected_server_identifier and \
                    (expected_server_identifier != dhcp_options[options.SERVER_IDENTIFIER]):
                stderr.writeline("skipping recv BOOTP packet : different server identifier {0}, expected {1}".format(
                    dhcp_options[options.SERVER_IDENTIFIER],
                    expected_server_identifier
                ))
                continue
            sname = network_types.decoders.cstring(sname)
            response_message = {
                "message_type": mtype,
                "source_ip":    source_ip,
                "dest_ip":      dest_ip,
                "cip":          cip,
                "yip":          yip,
                "sip":          sip,
                "gip":          gip,
                "options":      dhcp_options,
                "sname":        sname,
                "shaddr":       source_haddr
            }
            stdout.writeline("recieved DHCP/BOOTP {0} message from {1}:{2} to :{3} on nic {4}".format(
                mtype_name, source_ip, source_port, dest_port, nicname))
            stdout.write_named_dict(mtype_name, response_message)
            yield response_message
        except Exception as err:
            stderr.writeline("skipping recv DHCP/BOOTP recv exception : {0}".format(err))
            pass
    return
