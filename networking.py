# Python STDLIB
import struct
import socket
# Common
from common import hashobj
# Networking
import network_types

"""
# IANA Hardware Types

Hardware Type Codes defined by the IANA ARP standard. See
https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2 for more information.
"""

htypes = hashobj()

# Values

htypes.RESERVED0                               = 0
htypes.ETHERNET_10MBIT                         = 1
htypes.ETHERNET_EXPERIMENTAL                   = 2
htypes.AMATEUR_RADIO                           = 3
htypes.PROTEON_PRONET_TOKEN_RING               = 4
htypes.CHAOS                                   = 5
htypes.IEEE_802                                = 6
htypes.ARCNET                                  = 7
htypes.HYPERCHANNEL                            = 8
htypes.LANSTAR                                 = 9
htypes.AUTONET_SHORT_ADDRESS                   = 10
htypes.LOCALTALK                               = 11
htypes.LOCALNET                                = 12
htypes.ULTRA_LINK                              = 13
htypes.SMDS                                    = 14
htypes.FRAME_RELAY                             = 15
htypes.ASYNCHRONOUS_TRANSMISSION_MODE          = 16
htypes.HDLC                                    = 17
htypes.FIBRE_CHANNEL                           = 18
htypes.ASYNCHRONOUS_TRANSMISSION_MODE          = 19
htypes.SERIAL_LINE                             = 20
htypes.ASYNCHRONOUS_TRANSMISSION_MODE          = 21
htypes.MIL_STD_188_220                         = 22
htypes.METRICOM                                = 23
htypes.IEEE_1394_1995                          = 24
htypes.MAPOS                                   = 25
htypes.TWINAXIAL                               = 26
htypes.EUI_64                                  = 27
htypes.HIPARP                                  = 28
htypes.IP_AND_ARP_OVER_ISO_7816_3              = 29
htypes.ARPSEC                                  = 30
htypes.IPSEC_TUNNEL                            = 31
htypes.INFINIBAND                              = 32
htypes.TIA_102_PROJECT_25_COMMON_AIR_INTERFACE = 33
htypes.WIEGAND_INTERFACE                       = 34
htypes.PURE_IP                                 = 35
htypes.HW_EXP1                                 = 36
htypes.HFI                                     = 37

# Lookup Table

htypes.lookup = {
    htypes.RESERVED0:                               ("reserved0",                               6),
    htypes.ETHERNET_10MBIT:                         ("ethernet_10mbit",                         6),
    htypes.ETHERNET_EXPERIMENTAL:                   ("ethernet_experimental",                   6),
    htypes.AMATEUR_RADIO:                           ("amateur_radio",                           6),
    htypes.PROTEON_PRONET_TOKEN_RING:               ("proteon_pronet_token_ring",               6),
    htypes.CHAOS:                                   ("chaos",                                   6),
    htypes.IEEE_802:                                ("ieee_802",                                6),
    htypes.ARCNET:                                  ("arcnet",                                  6),
    htypes.HYPERCHANNEL:                            ("hyperchannel",                            6),
    htypes.LANSTAR:                                 ("lanstar",                                 6),
    htypes.AUTONET_SHORT_ADDRESS:                   ("autonet_short_address",                   6),
    htypes.LOCALTALK:                               ("localtalk",                               6),
    htypes.LOCALNET:                                ("localnet",                                6),
    htypes.ULTRA_LINK:                              ("ultra_link",                              6),
    htypes.SMDS:                                    ("smds",                                    6),
    htypes.FRAME_RELAY:                             ("frame_relay",                             6),
    htypes.ASYNCHRONOUS_TRANSMISSION_MODE:          ("asynchronous_transmission_mode",          6),
    htypes.HDLC:                                    ("hdlc",                                    6),
    htypes.FIBRE_CHANNEL:                           ("fibre_channel",                           6),
    htypes.ASYNCHRONOUS_TRANSMISSION_MODE:          ("asynchronous_transmission_mode",          6),
    htypes.SERIAL_LINE:                             ("serial_line",                             6),
    htypes.ASYNCHRONOUS_TRANSMISSION_MODE:          ("asynchronous_transmission_mode",          6),
    htypes.MIL_STD_188_220:                         ("mil_std_188_220",                         6),
    htypes.METRICOM:                                ("metricom",                                6),
    htypes.IEEE_1394_1995:                          ("ieee_1394_1995",                          6),
    htypes.MAPOS:                                   ("mapos",                                   6),
    htypes.TWINAXIAL:                               ("twinaxial",                               6),
    htypes.EUI_64:                                  ("eui_64",                                  6),
    htypes.HIPARP:                                  ("hiparp",                                  6),
    htypes.IP_AND_ARP_OVER_ISO_7816_3:              ("ip_and_arp_over_iso_7816_3",              6),
    htypes.ARPSEC:                                  ("arpsec",                                  6),
    htypes.IPSEC_TUNNEL:                            ("ipsec_tunnel",                            6),
    htypes.INFINIBAND:                              ("infiniband",                              6),
    htypes.TIA_102_PROJECT_25_COMMON_AIR_INTERFACE: ("tia_102_project_25_common_air_interface", 6),
    htypes.WIEGAND_INTERFACE:                       ("wiegand_interface",                       6),
    htypes.PURE_IP:                                 ("pure_ip",                                 6),
    htypes.HW_EXP1:                                 ("hw_exp1",                                 6),
    htypes.HFI:                                     ("hfi",                                     6)
}

"""
# EtherType

Network Ethernet Type Codes by the IEEE 802 Specification. See
https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml for more information.
"""

ethertype = hashobj()

# Values

ethertype.D802_3     = 0x0001
ethertype.AX25       = 0x0002
ethertype.ALL        = 0x0003
ethertype.F802_2     = 0x0004
ethertype.SNAP       = 0x0005
ethertype.DDCMP      = 0x0006
ethertype.WAN_PPP    = 0x0007
ethertype.PPP_MP     = 0x0008
ethertype.LOCALTALK  = 0x0009
ethertype.CAN        = 0x000C
ethertype.PPPTALK    = 0x0010
ethertype.TR_802_2   = 0x0011
ethertype.MOBITEX    = 0x0015
ethertype.CONTROL    = 0x0016
ethertype.IRDA       = 0x0017
ethertype.ECONET     = 0x0018
ethertype.HDLC       = 0x0019
ethertype.ARCNET     = 0x001A
ethertype.DSA        = 0x001B
ethertype.TRAILER    = 0x001C
ethertype.PHONET     = 0x00F5
ethertype.IEEE802154 = 0x00F6
ethertype.LOOP       = 0x0060
ethertype.PUP        = 0x0200
ethertype.PUPAT      = 0x0201
ethertype.IP         = 0x0800
ethertype.X25        = 0x0805
ethertype.ARP        = 0x0806
ethertype.BPQ        = 0x08FF
ethertype.IEEEPUP    = 0x0a00
ethertype.IEEEPUPAT  = 0x0a01
ethertype.DEC        = 0x6000
ethertype.DNA_DL     = 0x6001
ethertype.DNA_RC     = 0x6002
ethertype.DNA_RT     = 0x6003
ethertype.LAT        = 0x6004
ethertype.DIAG       = 0x6005
ethertype.CUST       = 0x6006
ethertype.SCA        = 0x6007
ethertype.TEB        = 0x6558
ethertype.RARP       = 0x8035
ethertype.ATALK      = 0x809B
ethertype.AARP       = 0x80F3
ethertype.V8021Q     = 0x8100
ethertype.IPX        = 0x8137
ethertype.IPV6       = 0x86DD
ethertype.PAUSE      = 0x8808
ethertype.SLOW       = 0x8809
ethertype.WCCP       = 0x883E
ethertype.PPP_DISC   = 0x8863
ethertype.PPP_SES    = 0x8864
ethertype.MPLS_UC    = 0x8847
ethertype.MPLS_MC    = 0x8848
ethertype.ATMMPOA    = 0x884c
ethertype.ATMFATE    = 0x8884
ethertype.PAE        = 0x888E
ethertype.AOE        = 0x88A2
ethertype.TIPC       = 0x88CA
ethertype.IEEE1588   = 0x88F7
ethertype.FCOE       = 0x8906
ethertype.FIP        = 0x8914
ethertype.FDSA       = 0xDADA

# Lookup Table

ethertype.lookup = {
    ethertype.D802_3:     ("d802_3",     "Dummy type for 802.3 frames"                                                ),
    ethertype.AX25:       ("ax25",       "Dummy protocol id for AX.25"                                                ),
    ethertype.ALL:        ("all",        "Every packet (be careful!!!)"                                               ),
    ethertype.F802_2:     ("f802_2",     "802.2 frames"                                                               ),
    ethertype.SNAP:       ("snap",       "Internal only"                                                              ),
    ethertype.DDCMP:      ("ddcmp",      "DEC DDCMP: Internal only"                                                   ),
    ethertype.WAN_PPP:    ("wan_ppp",    "Dummy type for WAN PPP frames"                                              ),
    ethertype.PPP_MP:     ("ppp_mp",     "Dummy type for PPP MP frames"                                               ),
    ethertype.LOCALTALK:  ("localtalk",  "Localtalk pseudo type"                                                      ),
    ethertype.CAN:        ("can",        "Controller Area Network"                                                    ),
    ethertype.PPPTALK:    ("ppptalk",    "Dummy type for Atalk over PPP"                                              ),
    ethertype.TR_802_2:   ("tr_802_2",   "802.2 frames"                                                               ),
    ethertype.MOBITEX:    ("mobitex",    "Mobitex (kaz@cafe.net)"                                                     ),
    ethertype.CONTROL:    ("control",    "Card specific control frames"                                               ),
    ethertype.IRDA:       ("irda",       "Linux-IrDA"                                                                 ),
    ethertype.ECONET:     ("econet",     "Acorn Econet"                                                               ),
    ethertype.HDLC:       ("hdlc",       "HDLC frames"                                                                ),
    ethertype.ARCNET:     ("arcnet",     "1A for ArcNet"                                                              ),
    ethertype.DSA:        ("dsa",        "Distributed Switch Arch."                                                   ),
    ethertype.TRAILER:    ("trailer",    "Trailer switch tagging"                                                     ),
    ethertype.PHONET:     ("phonet",     "Nokia Phonet frames"                                                        ),
    ethertype.IEEE802154: ("ieee802154", "IEEE802.15.4 frame"                                                         ),
    ethertype.LOOP:       ("loop",       "Ethernet Loopback packet"                                                   ),
    ethertype.PUP:        ("pup",        "Xerox PUP packet"                                                           ),
    ethertype.PUPAT:      ("pupat",      "Xerox PUP Addr Trans packet"                                                ),
    ethertype.IP:         ("ip",         "Internet Protocol packet"                                                   ),
    ethertype.X25:        ("x25",        "CCITT X.25"                                                                 ),
    ethertype.ARP:        ("arp",        "Address Resolution packet"                                                  ),
    ethertype.BPQ:        ("bpq",        "G8BPQ AX.25 Ethernet Packet [ NOT AN OFFICIALLY REGISTERED ID ]"            ),
    ethertype.IEEEPUP:    ("ieeepup",    "Xerox IEEE802.3 PUP packet"                                                 ),
    ethertype.IEEEPUPAT:  ("ieeepupat",  "Xerox IEEE802.3 PUP Addr Trans packet"                                      ),
    ethertype.DEC:        ("dec",        "DEC Assigned proto"                                                         ),
    ethertype.DNA_DL:     ("dna_dl",     "DEC DNA Dump/Load"                                                          ),
    ethertype.DNA_RC:     ("dna_rc",     "DEC DNA Remote Console"                                                     ),
    ethertype.DNA_RT:     ("dna_rt",     "DEC DNA Routing"                                                            ),
    ethertype.LAT:        ("lat",        "DEC LAT"                                                                    ),
    ethertype.DIAG:       ("diag",       "DEC Diagnostics"                                                            ),
    ethertype.CUST:       ("cust",       "DEC Customer use"                                                           ),
    ethertype.SCA:        ("sca",        "DEC Systems Comms Arch"                                                     ),
    ethertype.TEB:        ("teb",        "Trans Ether Bridging"                                                       ),
    ethertype.RARP:       ("rarp",       "Reverse Addr Res packet"                                                    ),
    ethertype.ATALK:      ("atalk",      "Appletalk DDP"                                                              ),
    ethertype.AARP:       ("aarp",       "Appletalk AARP"                                                             ),
    ethertype.V8021Q:     ("v8021q",     "802.1Q VLAN Extended Header"                                                ),
    ethertype.IPX:        ("ipx",        "IPX over DIX"                                                               ),
    ethertype.IPV6:       ("ipv6",       "IPv6 over bluebook"                                                         ),
    ethertype.PAUSE:      ("pause",      "IEEE Pause frames. See 802.3 31B"                                           ),
    ethertype.SLOW:       ("slow",       "Slow Protocol. See 802.3ad 43B"                                             ),
    ethertype.WCCP:       ("wccp",       "Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt"),
    ethertype.PPP_DISC:   ("ppp_disc",   "PPPoE discovery messages"                                                   ),
    ethertype.PPP_SES:    ("ppp_ses",    "PPPoE session messages"                                                     ),
    ethertype.MPLS_UC:    ("mpls_uc",    "MPLS Unicast traffic"                                                       ),
    ethertype.MPLS_MC:    ("mpls_mc",    "MPLS Multicast traffic"                                                     ),
    ethertype.ATMMPOA:    ("atmmpoa",    "MultiProtocol Over ATM"                                                     ),
    ethertype.ATMFATE:    ("atmfate",    "Frame-based ATM Transport over Ethernet"                                    ),
    ethertype.PAE:        ("pae",        "Port Access Entity (IEEE 802.1X)"                                           ),
    ethertype.AOE:        ("aoe",        "ATA over Ethernet"                                                          ),
    ethertype.TIPC:       ("tipc",       "TIPC"                                                                       ),
    ethertype.IEEE1588:   ("1588",       "IEEE 1588 Timesync"                                                         ),
    ethertype.FCOE:       ("fcoe",       "Fibre Channel over Ethernet"                                                ),
    ethertype.FIP:        ("fip",        "FCoE Initialization Protocol"                                               ),
    ethertype.FDSA:       ("fdsa",       "FCoE Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ]"                     )
}


"""
# Small UDP/IP/Ethernet Network Stack

Small UDP/IP/Ethernet network stack built to encapsulate and unpack raw data into and from packets in their binary
form.
"""


def in_cksum(data):
    """
    Net Checksum Function

    Python version of:
    http://www.cs.cmu.edu/afs/cs/academic/class/15213-f00/unpv12e/libfree/in_cksum.c

    Parameters:
    data (bytes): binary data to find the checksum of

    Returns
    int: 16 bit checksum value as integer
    """
    csum = 0
    # Using a 32 bit accumulator (sum), we add sequential 16 bit words
    # and at the end, fold carry bits from the top 16 bit words to the
    # lower 16 bit words
    for i in range(0, len(data) - 1, 2):
        csum += ((data[i] << 8) & 0xFF00) + (data[i + 1] & 0x00FF)
    # Mop up an odd byte if necessary
    if len(data) % 2 == 1:
        csum += data[len(data) - 1] & 0x00FF
    # Add back carry outs from top 16 bits to low 16 bits
    while csum >> 16:
        csum = (csum >> 16) + (csum & 0xFFFF)
    # Ones Compliment and truncate to 16 bits
    csum = (~csum) & 0xffff
    return csum


class ethernet():
    """
    Class to handle minimal Ethernet frames

    Ethernet Header reference Diagram:

    0                   1                   2                   3                   4                   5
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Destination MAC Address           |               Source MAC Address              |    Ethertype    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                  Data Bytes......
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+......
    """
    @staticmethod
    def encapsulate(source_mac, dest_mac, packet):
        """
        Encapsulate a Network Layer packet with a simple Ethernet header and return the resulting
        Link Layer frame.

        Parameters:
        source_mac (str): colon seperated hex string of the source MAC address
        dest_mac (str): colon seperated hex string of the destination MAC address
        packet (bytes): binary packet

        Returns:
        bytes: assembled ethernet frame
        """
        # Ethernet Header
        buffer = b""
        # [ 14 Bytes ] Dest Mac | Source Mac | Ethertype (IP)
        buffer += struct.pack(
            "!6s6sH",
            network_types.encoders.ethermac(dest_mac),
            network_types.encoders.ethermac(source_mac),
            ethertype.IP
        )
        # Network Layer Packet
        buffer += packet
        return buffer

    @staticmethod
    def encapsulate_broadcast(source_mac, packet):
        """
        Decorator to Encapsulate a Network Layer packet with a broadcast Ethernet header where the dest mac is always
        "FF:FF:FF:FF:FF:FF"

        Parameters:
        source_mac (str): colon seperated hex string of the source MAC address
        packet (bytes): binary packet

        Returns:
        bytes: assembled ethernet frame
        """
        dest_mac = "FF:FF:FF:FF:FF:FF"
        return ethernet.encapsulate(source_mac, dest_mac, packet)

    @staticmethod
    def unpack(frame_buffer):
        """
        Unpack the contents of the Ethernet Frame and return it

        Parameters:
        frame_buffer (bytes): binary byte buffer containing the ethernet frame

        Returns
        tuple(str, str, int, bytes): tuple containing the dest_mac, source_mac, ethertype and binary packet
        """
        packet = frame_buffer[14:]
        (dest_mac, source_mac, ethertype) = struct.unpack("!6s6sH", frame_buffer[:14])
        dest_mac = network_types.decoders.ethermac(dest_mac)
        source_mac = network_types.decoders.ethermac(source_mac)
        return (dest_mac, source_mac, ethertype, packet)


class ipv4():
    """
    Class to handle IPv4 related functions and metadata.

    IPv4 reference packet diagram:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Data Bytes......
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+......
    """
    # Default IP Layer TTL
    DEFAULT_TTL = 20

    # Method to encapsulate an IP packet with an IP Header
    @staticmethod
    def encapsulate(source_ip, dest_ip, identification, segment):
        """
        Encapsulate a Transport Layer Segment with an IPv4 header and return the
        resulting IPv4 Packet. No IPv4 options are set.

        Parameters:
        source_ip (str): source ip string
        dest_ip (str): dest ip string
        identification (int): 16 bit IP identification
        segment (bytes): binary segment

        Returns:
        bytes: assembled ip packet
        """
        # IP Header
        buffer = b""
        buffer += struct.pack("!BBH", (5 | (4 << 4)), 0, len(segment) + 20)     # 4 Bytes
        buffer += struct.pack("!HH", identification, 0)                         # 4 Bytes
        buffer += struct.pack("!BBH", ipv4.DEFAULT_TTL, socket.IPPROTO_UDP, 0)  # 4 Bytes
        buffer += network_types.encoders.ip(source_ip)                                    # 4 Bytes
        buffer += network_types.encoders.ip(dest_ip)                                      # 4 Bytes
        # Calculate and update the Header Checksum
        csum = in_cksum(buffer)
        buffer = buffer[0:10] + struct.pack("!H", csum) + buffer[12:]
        # Transport Layer Segment
        buffer += segment
        return buffer

    @staticmethod
    def encapsulate_broadcast(identification, segment):
        """
        Decorator to encapsulate a Transport Layer Segment with an IPv4 header for broadcast

        Parameters:
        identification (int): 16 bit IP identification
        segment (bytes): binary segment

        Returns:
        bytes: assembled ip packet
        """
        source_ip = "0.0.0.0"
        dest_ip = "255.255.255.255"
        return ipv4.encapsulate(source_ip, dest_ip, identification, segment)

    @staticmethod
    def unpack(packet_buffer):
        """
        Unpack the contents of the IPv4 packet and return it

        Parameters:
        packet_buffer (bytes): binary byte buffer containing the ip packet

        Returns
        tuple(int, int, int, str, str,  bytes): tuple containing the identification, ttl, proto, source_ip, dest_ip and
            binary segment
        """
        version_ihl, tos, total_length, identification, flag_offset, ttl, proto, csum = \
            struct.unpack("!BBHHHBBH", packet_buffer[:12])
        # Validate the packet
        version = (version_ihl >> 4) & 0xF
        ihl = version_ihl & 0xF
        ihl_bytes = ihl*4
        if version != 4:
            raise Exception("Packet is not an IPv4 packet.")
        if len(packet_buffer) != total_length:
            raise Exception("Packet size mismatch with IP Header.")
        # Validate the Checksum
        packet_header_cksum_check = packet_buffer[0:10] + struct.pack("!H", 0) + packet_buffer[12:(ihl_bytes)]
        expected_csum = in_cksum(packet_header_cksum_check)
        if expected_csum != csum:
            raise Exception("Packet checksum mismatch, expected {0:x}, got {1:x}.".format(expected_csum, csum))
        segment = packet_buffer[ihl_bytes:]
        source_ip = network_types.decoders.ip(packet_buffer[12:16])
        dest_ip = network_types.decoders.ip(packet_buffer[16:20])
        return (identification, ttl, proto, source_ip, dest_ip, segment)


class udp():
    """
    Class to handle UDP related functions and metadata.

    UDP reference packet diagram:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |        Destination Port       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             Length            |          UDP Checksum         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Data Bytes......
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+......

    The UDP checksum is not calculated over the UDP packet but over the
    UDP packet attacked to a Pseudo Header like so:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Zeroes     |    Protocol   |           UDP Length          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |        Destination Port       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             Length            |          UDP Checksum         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Data Bytes......
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+......
    """
    @staticmethod
    def encapsulate(source_ip, dest_ip, source_port, dest_port, data):
        """
        Encapsulate Application Layer Data with a Checksummed UDP header and
        return the resulting UDP Segment.

        Parameters:
        source_ip (str): source ip string
        dest_ip (str): dest ip string
        source_port (int): source port
        dest_port (int): dest port
        data (bytes): application data

        Returns:
        bytes: assembled udp segment/datagram
        """
        udp_length = 8 + len(data)
        # UDP Header
        buffer = b""
        buffer += struct.pack("!HH", source_port, dest_port)  # 4 bytes
        buffer += struct.pack("!HH", udp_length, 0)           # 4 bytes
        # Application Data
        buffer += data
        # Calculate and update the UDP checksum
        udp_pseudo_packet = b""
        udp_pseudo_packet += network_types.encoders.ip(source_ip)
        udp_pseudo_packet += network_types.encoders.ip(dest_ip)
        udp_pseudo_packet += struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_length)
        udp_pseudo_packet += buffer
        csum = in_cksum(udp_pseudo_packet)
        buffer = buffer[:6] + struct.pack("!H", csum) + buffer[8:]
        # Return the binary buffer
        return buffer

    @staticmethod
    def encapsulate_broadcast(source_port, dest_port, data):
        """
        Decorator to encapsulate Application Data with an UDP header for broadcast.

        Parameters:
        source_port (int): source port
        dest_port (int): dest port
        data (bytes): application data

        Returns:
        bytes: assembled udp segment/datagram
        """
        source_ip = "0.0.0.0"
        dest_ip = "255.255.255.255"
        return udp.encapsulate(source_ip, dest_ip, source_port, dest_port, data)

    @staticmethod
    def unpack(source_ip, dest_ip, segment_buffer):
        """
        Unpack and validate the contents of the UDP segment and return it.

        Parameters:
        source_ip (str): source ip
        dest_ip (str): source ip
        segment_buffer (bytes): binary byte buffer containing the udp segment

        Returns
        tuple(int, int, bytes): tuple containing the source_port, dest_port and binary application_data
        """
        source_port, dest_port, udp_length, csum = struct.unpack("!HHHH", segment_buffer[:8])
        if len(segment_buffer) != udp_length:
            raise Exception("Packet size mismatch with UDP Header.")
        application_data  = segment_buffer[8:]
        udp_pseudo_packet = b""
        udp_pseudo_packet += network_types.encoders.ip(source_ip)
        udp_pseudo_packet += network_types.encoders.ip(dest_ip)
        udp_pseudo_packet += struct.pack("!BBH", 0, socket.IPPROTO_UDP, udp_length)
        udp_pseudo_packet += segment_buffer[:6]
        udp_pseudo_packet += struct.pack("!H", 0)
        udp_pseudo_packet += segment_buffer[8:]
        if csum != 0:
            expected_csum = in_cksum(udp_pseudo_packet)
            if expected_csum != csum:
                raise Exception("Segment checksum mismatch, expected {0:0x}, got {1:0x}.".format(expected_csum, csum))
        application_data = segment_buffer[8:]
        return (source_port, dest_port, application_data)
