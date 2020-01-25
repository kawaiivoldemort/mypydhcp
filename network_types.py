"""
Library of network types and buffer handlers
"""

# Python STDLIB
import struct
import socket


class encoders():
    """
    # Network Type Encoders

    Small library of encoders of various data types from their python object form to binary network buffers.
    """

    @staticmethod
    def ip(ip_string):
        """
        Encodes an IP address to binary from its string

        Takes an IP from a binary integer representation and converts it to a network order binary encoded integer.

        Parameters:
        ip_string (str): ASCII IP string representation

        Returns:
        bytes: Binary 4 byte buffer representing an IP integer
        """
        return socket.inet_aton(ip_string)

    @staticmethod
    def iplist(ip_string_list):
        """
        Encodes an IP address list to a network order binary

        Takes a list of IP strings, convert them to their four byte binary integer representations in network order, and
        concatenates them into a single binary string.

        Parameters:
        ip_string_list (list): list of ASCII IP string representations

        Returns:
        bytes: Binary buffer representing an IP list (multiple of 4)
        """
        buffer = b""
        for ip_string in ip_string_list:
            buffer += socket.inet_aton(ip_string)
        return buffer

    @staticmethod
    def ippairs(ip_string_pair_list):
        """
        Encodes an IP address pair list to a network order binary

        Takes a list of IP string pairs in tuples, converts them to their four byte binary integer representations in
        network order, and concatenates them into a single binary string.

        Parameters:
        ip_string_pair_list (list): list of ASCII IP string pair tuples

        Returns:
        bytes: Binary buffer representing an IP list (multiple of 8)
        """
        buffer = b""
        for ip_string_pair in ip_string_pair_list:
            buffer += socket.inet_aton(ip_string_pair[0])
            buffer += socket.inet_aton(ip_string_pair[1])
        return buffer

    @staticmethod
    def ethermac(mac_string):
        """
        Encodes a 6 byte ethernet MAC address to network order binary

        Takes a 6 byte ethernet MAC address in its colon seperated hex string format and  converts it to its network
        order binary representation.

        Parameters:
        mac_string (str): MAC address string

        Returns:
        buffer (bytes): Binary buffer representing an Ethernet MAC (6 bytes long)
        """
        assert(len(mac_string) == 17)
        return bytes.fromhex(mac_string.replace(":", "").replace("-", ""))

    @staticmethod
    def uint8(number):
        """
        Encodes a 1 byte integer to its network order binary

        Parameters:
        number (int): integer

        Returns:
        bytes: Binary buffer representing an integer (1 byte long)
        """
        assert(isinstance(number, int))
        assert((number & 0xFF) == number)
        return struct.pack("!B", number)

    @staticmethod
    def uint8list(number_list):
        """
        Encodes a list of 1 byte integers to network order binary

        Parameters:
        number_list (list): 1 byte integer list

        Returns:
        bytes: Binary buffer representing a list of 1 byte long integers
        """
        buffer = b""
        for number in number_list:
            buffer += encoders.uint8(number)
        return buffer

    @staticmethod
    def uint16(number):
        """
        Encodes a 2 byte integer to its network order binary

        Parameters:
        number (int): integer

        Returns:
        bytes: Binary buffer representing an integer (2 bytes long)
        """
        assert(isinstance(number, int))
        assert((number & 0xFFFF) == number)
        return struct.pack("!H", number)

    @staticmethod
    def uint32(number):
        """
        Encodes a 4 byte integer to its network order binary

        Parameters:
        number (int): integer

        Returns:
        bytes: Binary buffer representing an integer (4 bytes long)
        """
        assert(isinstance(number, int))
        assert((number & 0xFFFFFFFF) == number)
        return struct.pack("!I", number)

    @staticmethod
    def uint64(number):
        """
        Encodes a 8 byte integer to its network order binary

        Parameters:
        number (int): integer

        Returns:
        bytes: Binary buffer representing an integer (8 bytes long)
        """
        assert(isinstance(number, int))
        assert((number & 0xFFFFFFFFFFFFFFFF) == number)
        return struct.pack("!Q", number)

    @staticmethod
    def cbool(bool_value):
        """
        Encodes an boolean value to a 1 byte network order binary containing either 0 or 1

        Parameters:
        bool_value (bool): True or False

        Returns:
        bytes: Binary buffer representing a boolean value (1 byte long)
        """
        if bool_value:
            return struct.pack("!B", 1)
        else:
            return struct.pack("!B", 0)

    @staticmethod
    def cstring(string_value):
        """
        Encodes a C string to a network order binary buffer

        Converts a python string to its null terminated ASCII representation in network order binary.

        Parameters:
        string_value (str): string value

        Returns:
        bytes: Binary buffer representing an integer (8 byte long)
        """
        assert(isinstance(string_value, str))
        if string_value[-1] != "\0":
            string_value += "\0"
        return struct.pack("!s", bytes(string_value, "utf-8"))


class decoders():
    """
    # Network Type Decoders

    Small library of decoders of various data types from their network buffer format to their corresponding python form.
    """

    @staticmethod
    def ip(buffer):
        """
        Decodes an IP address from network order binary

        Takes an IP from a network order binary integer representation and converts it to an ascii string such as
        "1.1.1.1".

        Parameters:
        buffer (bytes): Binary 4 byte buffer representing an IP integer

        Returns:
        str: ASCII IP string representation
        """
        assert(len(buffer) == 4)
        return socket.inet_ntoa(buffer)

    @staticmethod
    def iplist(buffer):
        """
        Decodes an IP address list from network order binary

        Takes 4 byte chunks of a network order binary string, assumes them to be IPs and converts them to their ascii
        representations.

        Parameters:
        buffer (bytes): Binary buffer representing an IP list (multiple of 4)

        Returns:
        list: list of ASCII IP string representations
        """
        ip_list = []
        buflen = len(buffer)
        assert(((buflen >> 2) << 2) == buflen)
        while(buffer):
            ip_list.append(socket.inet_ntoa(buffer[:4]))
            buffer = buffer[4:]
        return ip_list

    @staticmethod
    def ippairs(buffer):
        """
        Decodes an IP address pair list from network order binary

        Takes 8 byte chunks of a network order binary string, assumes them to be IP pairs and converts them to their
        ascii representations.

        Parameters:
        buffer (bytes): Binary buffer representing an IP pair list (multiple of 8)

        Returns:
        list: list of tuples of ASCII IP string pairs
        """
        ip_pairs = []
        buflen = len(buffer)
        assert(((buflen >> 3) << 3) == buflen)
        while(buffer):
            # (ip1, ip2)
            ip_pairs.append(
                (
                    socket.inet_ntoa(buffer[:4]),
                    socket.inet_ntoa(buffer[4:8])
                )
            )
            buffer = buffer[4:]
        return ip_pairs

    @staticmethod
    def ethermac(buffer):
        """
        Decodes a 6 byte ethernet MAC address from network order binary

        Takes 6 byte chunks network order binary representation of an ethernet MAC address and converts it to its colon
        seperated hex string format.

        Parameters:
        buffer (bytes): Binary buffer representing an Ethernet MAC (6 bytes long)

        Returns:
        str: MAC address string
        """
        assert(len(buffer) == 6)
        return "{0:02x}:{1:02x}:{2:02x}:{3:02x}:{4:02x}:{5:02x}".format(
            *struct.unpack("!BBBBBB", buffer)
        )

    @staticmethod
    def uint8(buffer):
        """
        Decodes a 1 byte integer from network order binary

        Parameters:
        buffer (bytes): Binary buffer representing an integer (1 byte long)

        Returns:
        int: integer
        """
        assert(len(buffer) == 1)
        return struct.unpack("!B", buffer)[0]

    @staticmethod
    def uint8list(buffer):
        """
        Decodes a list of 1 byte integers from network order binary

        Parameters:
        buffer (bytes): Binary buffer representing a list of 1 byte long integers

        Returns:
        list: 1 byte integer list
        """
        return [struct.unpack("!B", c)[0] for c in buffer]

    @staticmethod
    def uint16(buffer):
        """
        Decodes a 2 byte integer from network order binary

        Parameters:
        buffer (bytes): Binary buffer representing an integer (2 byte long)

        Returns:
        int: integer
        """
        assert(len(buffer) == 1)
        return struct.unpack("!H", buffer)[0]

    @staticmethod
    def uint32(buffer):
        """
        Decodes a 4 byte integer from network order binary

        Parameters:
        buffer (bytes): Binary buffer representing an integer (4 byte long)

        Returns:
        int: integer
        """
        assert(len(buffer) == 4)
        return struct.unpack("!I", buffer)[0]

    @staticmethod
    def uint64(buffer):
        """
        Decodes an 8 byte integer from network order binary

        Parameters:
        buffer (bytes): Binary buffer representing an integer (8 byte long)

        Returns:
        int: integer
        """
        assert(len(buffer) == 4)
        return struct.unpack("!Q", buffer)[0]

    @staticmethod
    def cbool(buffer):
        """
        Decodes an bool from a 1 byte network order binary

        Parameters:
        buffer (bytes): Binary buffer representing a boolean value (1 byte long)

        Returns:
        bool: True or False
        """
        return (buffer != 0)

    @staticmethod
    def cstring(buffer, length=0):
        """
        Decodes a C string from a network order binary buffer

        Takes a null terminated and ASCII binary string and encodes it as a python string.

        Parameters:
        buffer (bytes): Binary buffer representing an integer (8 byte long)

        Returns:
        str: string value
        """
        if isinstance(buffer, str):
            if '\x00' in buffer:
                buffer = buffer[:buffer.index('\x00')]
        elif isinstance(buffer, bytes):
            if b'\x00' in buffer:
                buffer = buffer[:buffer.index(b'\x00')]
            try:
                buffer = buffer.decode("ascii")
            except Exception:
                try:
                    buffer = buffer.decode("utf-8")
                except Exception:
                    pass
        return buffer


class validaters():
    """
    # Network Type Validaters

    Small library of input validaters for the network type encoders.
    """

    @staticmethod
    def ip(ip_string):
        """
        Returns true if the IP string is a valid IP

        Parameters:
        ip_string (str): ASCII IP string representation

        Returns:
        bool: Whether the IP is valid
        """
        try:
            socket.inet_aton(ip_string)
        except socket.error:
            return False
        return True

    @staticmethod
    def iplist(ip_string_list):
        """
        Returns true if all the IP strings in the List are valid IPs

        Parameters:
        ip_string_list (list): list of ASCII IP string representations

        Returns:
        bool: Whether the IPs are valid
        """
        for ip_string in ip_string_list:
            try:
                socket.inet_aton(ip_string)
            except socket.error:
                return False
        return True

    @staticmethod
    def ippairs(ip_string_pair_list):
        """
        Returns true if all the IP strings in the IP Pair list are valid IPs

        Parameters:
        ip_string_pair_list (list): list of ASCII IP string pair tuples

        Returns:
        bool: Whether the IPs are valid
        """
        for ip_string_pair in ip_string_pair_list:
            try:
                socket.inet_aton(ip_string_pair[0])
                socket.inet_aton(ip_string_pair[1])
            except socket.error:
                return False
        return True

    @staticmethod
    def ethermac(mac_string):
        """
        Returns true if the string is a valid 6 byte ethernet MAC address

        Parameters:
        mac_string (str): MAC address string

        Returns:
        bool: Whether the mac is valid
        """
        try:
            assert(len(mac_string) == 17)
            mac_string = mac_string.split(":")
            assert(len(mac_string) == 6)
            assert(all(len(x) == 2 for x in mac_string))
            assert(all((x & 0xff) == x for x in [int(y, 16) for y in mac_string]))
        except Exception:
            return False
        return True

    @staticmethod
    def uint8(number):
        """
        Returns true if the number is a valid 1 byte integer

        Parameters:
        number (int): integer

        Returns:
        bool: Whether the input is a 1 byte integer
        """
        try:
            assert(isinstance(number, int))
            assert((number & 0xff) == number)
        except Exception:
            return False
        return True

    @staticmethod
    def uint8list(number_list):
        """
        Returns true if the numbers on the list are all valid 1 byte integers

        Parameters:
        number (int): integer

        Returns:
        bool: Whether the input is all 1 byte integers
        """
        if all(validaters.uint8(n) for n in number_list):
            return True
        return False

    @staticmethod
    def uint16(number):
        """
        Returns true if the number is a valid 2 byte integer

        Parameters:
        number (int): integer

        Returns:
        bool: Whether the input is a 2 byte integer
        """
        try:
            assert(isinstance(number, int))
            assert((number & 0xffff) == number)
        except Exception:
            return False
        return True

    @staticmethod
    def uint32(number):
        """
        Returns true if the number is a valid 4 byte integer

        Parameters:
        number (int): integer

        Returns:
        bool: Whether the input is a 4 byte integer
        """
        try:
            assert(isinstance(number, int))
            assert((number & 0xffffffff) == number)
        except Exception:
            return False
        return True

    @staticmethod
    def uint64(number):
        """
        Returns true if the number is a valid 8 byte integer

        Parameters:
        number (int): integer

        Returns:
        bool: Whether the input is a 8 byte integer
        """
        try:
            assert(isinstance(number, int))
            assert((number & 0xffffffffffffffff) == number)
        except Exception:
            return False
        return True

    @staticmethod
    def cbool(bool_value):
        """
        Always returns True

        Parameters:
        bool_value (bool): True or False

        Returns:
        bool: True
        """
        return True

    @staticmethod
    def cstring(string_value):
        """
        Returns true if the input is a python string

        Parameters:
        string_value (str): string value

        Returns:
        bool: Whether the input is a python string
        """
        if isinstance(string_value, str):
            return True
        return False
