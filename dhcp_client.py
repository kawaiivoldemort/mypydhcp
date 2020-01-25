"""
DHCP Client Implementation
"""

# Python STDLIB
import os.path
import time
import json
import random
# Networking
from networking import htypes
# Network types
import network_types
# DHCP
import dhcp
# Process
process import daemon
# Common
common import hashobj, stdout, stderr

"""
# DHCP Client States

Contains the DHCP Client States, their IDs and a lookup table to get their names.
"""

states = hashobj()

# Values

states.BOOT        = 0
states.INIT        = 1
states.SELECTING   = 2
states.REQUESTING  = 3
states.BOUND       = 4
states.RENEWING    = 5
states.REBINDING   = 6
states.EXITING     = 7
states.INIT_REBOOT = 8
states.REBOOTING   = 9
states.SHUT_DOWN   = 10

# Lookup Table

states.lookup = {
    states.BOOT:        "boot",
    states.INIT:        "init",
    states.SELECTING:   "selecting",
    states.REQUESTING:  "requesting",
    states.BOUND:       "bound",
    states.RENEWING:    "renewing",
    states.REBINDING:   "rebinding",
    states.EXITING:     "exiting",
    states.INIT_REBOOT: "init_reboot",
    states.REBOOTING:   "rebooting",
    states.SHUT_DOWN:   "shut_down"
}


class client(daemon):
    """
    Defines a DHCP Client with the following state transitions:
        --------                               -------
        |        | +-------------------------->|       |<-------------------+
        | INIT-  | |     +-------------------->| INIT  |                    |
        | REBOOT |DHCPNAK/         +---------->|       |<---+               |
        |        |Restart|         |            -------     |               |
        --------  |  DHCPNAK/     |               |                        |
            |      Discard offer   |      -/Send DHCPDISCOVER               |
        -/Send DHCPREQUEST         |               |                        |
            |      |     |      DHCPACK            v        |               |
        -----------     |   (not accept.)/   -----------   |               |
        |           |    |  Send DHCPDECLINE |           |                  |
        | REBOOTING |    |         |         | SELECTING |<----+            |
        |           |    |        /          |           |     |DHCPOFFER/  |
        -----------     |       /            -----------   |  |Collect     |
            |            |      /                  |   |       |  replies   |
        DHCPACK/         |     /  +----------------+   +-------+            |
        Record lease, set|    |   v   Select offer/                         |
        timers T1, T2   ------------  send DHCPREQUEST      |               |
            |   +----->|            |             DHCPNAK, Lease expired/   |
            |   |      | REQUESTING |                  Halt network         |
            DHCPOFFER/ |            |                       |               |
            Discard     ------------                        |               |
            |   |        |        |                   -----------           |
            |   +--------+     DHCPACK/              |           |          |
            |              Record lease, set    -----| REBINDING |          |
            |                timers T1, T2     /     |           |          |
            |                     |        DHCPACK/   -----------           |
            |                     v     Record lease, set   ^               |
            +----------------> -------      /timers T1,T2   |               |
                    +----->|       |<---+                |               |
                    |      | BOUND |<---+                |               |
        DHCPOFFER, DHCPACK, |       |    |            T2 expires/   DHCPNAK/
        DHCPNAK/Discard     -------     |             Broadcast  Halt network
                    |       | |         |            DHCPREQUEST         |
                    +-------+ |        DHCPACK/          |               |
                            T1 expires/   Record lease, set |               |
                        Send DHCPREQUEST timers T1, T2     |               |
                        to leasing server |                |               |
                                |   ----------             |               |
                                |  |          |------------+               |
                                +->| RENEWING |                            |
                                    |          |----------------------------+
                                    ----------
    """
    @staticmethod
    def _get_lease(interface_name, offered_ip, server_ip, server_name, server_haddr, dhcp_options, dhcp_ack,
                   lease_file):
        """
        Gets a lease from a (DHCP Offer || Old Lease) and a DHCP Ack

        Parameters:
        interface_name (str): interface_name
        offered_ip (str): offered_ip from an old lease or a DHCP Offer (yip)
        server_ip (str): server_ip from an old lease or a DHCP Offer (options/server_identifier)
        server_name (str): server_name from an old lease or a DHCP Offer (sname)
        server_haddr (str): server_haddr from an old lease or a DHCP Offer
        dhcp_options (str): dhcp_options from an old lease or a DHCP Offer
        dhcp_ack (dict): DHCP Acknowledgement Message

        Returns:
        dict: the DHCP Lease
        """
        # Get the Renewing and Rebinding times, default is Renew = 50% lease, Rebind = 87.5% lease. We offset time by
        # -10 since time taken is from the time of sending the DHCPRequest and not from when the DHCPACK was recieved.
        dhcp_options.update(dhcp_ack["options"])
        lease_time = dhcp_options[dhcp.options.IP_ADDRESS_LEASE_TIME]
        rebinding_time = (12.5 * lease_time) / 100
        renewing_time = rebinding_time * 4
        expiry_time = lease_time + int(time.time()) - 10
        rebinding_time = expiry_time - rebinding_time
        renewing_time = expiry_time - renewing_time
        renewing_time = int(time.time()) + dhcp_options[dhcp.options.RENEWAL_TIME_VALUE] - 10
        rebinding_time = int(time.time()) + dhcp_options[dhcp.options.REBINDING_TIME_VALUE] - 10
        subnet_mask = dhcp_options[dhcp.options.SUBNET_MASK]
        gateway = dhcp_options[dhcp.options.ROUTER]
        # Assemble and return the Lease
        lease = {
            "interface":     interface_name,
            "ip":            offered_ip,
            "subnet_mask":   subnet_mask,
            "gateways":      gateway,
            "dhcp_server":   {
                "ip":          server_ip,
                "name":        server_name,
                "mac_address": server_haddr
            },
            "options":       dhcp_options,
            "renew":         renewing_time,
            "rebind":        rebinding_time,
            "expire":        expiry_time
        }
        with open(lease_file, 'w') as fd:
            fd.write(json.dumps([lease], indent=4))
        return lease

    def __init__(self, interface_name, chaddr):
        """
        Constructor
        """
        # Set the object fields
        self.interface_name = interface_name
        self.chaddr = chaddr
        self.xid  = int(random.random() * 0xffffffff)               # Transaction ID
        self.starttime = int(time.time())
        self.channel = dhcp.open_raw_client_channel(self.interface_name, 0)
        self.state = states.SHUT_DOWN
        self.lease = None
        self.hops = 0
        self.htype = htypes.ETHERNET_10MBIT
        self.select_dhcp_offers = None
        self.select_offer_id = None
        self.request_dhcp_offer = None
        self.lease_file = "./dhcp.{0}.leases".format(self.interface_name)
        self.name = "dhcp_client_{0}".format(self.interface_name)
        self.event_callbacks = []
        self.thread = None

    def __str__(self):
        """
        Get the DHCP Client Name
        """
        return self.name

    def status(self):
        """
        Get a tuple containing the DHCP Client service name and status
        """
        status_dict = {
            "xid":         self.xid,
            "starttime":   self.starttime,
            "mac_address": self.chaddr,
            "htype":       htypes.lookup(self.htype),
            "state":       states.lookup(self.state),
            "lease":       self.lease
        }
        return (self.name, status_dict)

    def boot(self, end_time):
        """
        DHCP Client Bootup State

        - Handles both boot and reboot/init_reboot functioning.
        - If an existing lease exists, will try to load and call the reboot function on existing leases.
        - If no leases file found, will simply call the init state to acquire a lease.
        """
        stdout.writeline("BOOT", prefix=self.name)
        self.state = states.INIT
        if os.path.isfile(self.lease_file):
            leases = None
            with open(self.lease_file) as file:
                leases = file.read()
                try:
                    leases = json.loads(leases)
                    if not isinstance(leases, list):
                        stderr.writeline("invalid lease : {0}".format(leases))
                        leases = None
                except json.JSONDecodeError as e:
                    os.remove(self.lease_file)
                    stderr.writeline("invalid lease json : {0}".format(e))
            if leases is not None:
                self.state = states.INIT_REBOOT
                self.init_reboot(leases)

    def init(self, end_time):
        """
        DHCP Client Init State

        - Sends out a DHCP discover.
        - Tries to call the selecting state on response DHCP offers.
        """
        self.lease = None
        if os.path.isfile(self.lease_file):
            os.remove(self.lease_file)
        self.do_event_callbacks()
        # Broadcast DHCP Discovers to find the DHCP Server
        stdout.writeline("INIT", prefix=self.name)
        try:
            dhcp.send(
                mtype=dhcp.message_types.DISCOVER,
                hops=0,
                htype=self.htype,
                xid=self.xid,
                dhcp_flags=dhcp.flags.BROADCAST,
                secs=int(time.time()) - self.starttime,
                chaddr=self.chaddr,
                raw_channel=self.channel,
                nicname=self.interface_name
            )
        except dhcp.error as err:
            stderr.writeline(err)
            self.state = states.SHUT_DOWN
            return
        # Generator to get DHCP Offers
        dhcp_offers = dhcp.receive(
            mtypes=[dhcp.message_types.OFFER],
            expected_chaddr=self.chaddr,
            expected_xid=self.xid,
            raw_channel=self.channel,
            end_time=end_time,
            nicname=self.interface_name
        )
        # Immediately call select since the DHCP server waits for noone
        self.state = states.SELECTING
        self.select_dhcp_offers = list(dhcp_offers)
        self.select_offer_id = -1

    def selecting(self, end_time):
        """
        DHCP Client Selecting State

        - Tries to select an offer by calling the requesting state all offers.
        """
        # Try and Request on each Offer till bound
        stdout.writeline("SELECTING", prefix=self.name)
        if not self.select_dhcp_offers or not self.select_offer_id:
            self.state = states.SHUT_DOWN
        self.select_offer_id += 1
        if self.select_offer_id >= len(self.select_dhcp_offers):
            # Expired offers
            self.select_dhcp_offers = None
            self.select_offer_id = None
            self.state = states.INIT
        else:
            # Request for the offer
            self.request_dhcp_offer = self.select_dhcp_offers[self.select_offer_id]
            self.state = states.REQUESTING

    def request_and_bind(self, end_time):
        """
        Assemble a DHCP Request from a DHCP offer or old lease and send it, then wait for an ACK or
        NACK. Goto INIT if NACK, BOUND if ACK or dont change state if neither.
        """
        # Check that the state is valid
        if self.state not in [states.REQUESTING, states.RENEWING, states.REBINDING, states.REBOOTING]:
            return
        state_name = states.lookup[self.state]
        stdout.writeline(state_name.upper(), prefix=self.name)
        # Assemble the DHCP Request Parameters below
        expected_dest_ip = None
        expected_yip = None
        expected_server_identifier = None
        sname = None
        shaddr = None
        options = None
        dhcp_flags = None
        default_routers = None
        request_options = None
        if self.state == states.REQUESTING:
            expected_dest_ip = "0.0.0.0"
            expected_yip = self.request_dhcp_offer["yip"]
            expected_server_identifier = self.request_dhcp_offer["options"][dhcp.options.SERVER_IDENTIFIER]
            sname = self.request_dhcp_offer["sname"]
            shaddr = self.request_dhcp_offer["shaddr"]
            options = self.request_dhcp_offer["options"]
            dhcp_flags = dhcp.flags.BROADCAST
            if dhcp.options.ROUTER in self.request_dhcp_offer["options"]:
                default_routers = self.request_dhcp_offer["options"][dhcp.options.ROUTER]
            # We have a DHCP Offer
            request_options = {
                dhcp.options.REQUESTED_IP_ADDRESS:   expected_yip,
                dhcp.options.SERVER_IDENTIFIER:      expected_server_identifier,
                dhcp.options.PARAMETER_REQUEST_LIST: [
                    dhcp.options.SUBNET_MASK,
                    dhcp.options.ROUTER,
                    dhcp.options.DOMAIN_SERVER
                ]
            }
        else:
            # We already have a lease we are trying to renew or extend
            expected_dest_ip = self.lease["ip"]
            expected_yip = expected_dest_ip
            expected_server_identifier = self.lease["dhcp_server"]["ip"]
            sname = self.lease["dhcp_server"]["name"]
            shaddr = self.lease["dhcp_server"]["mac_address"]
            options = self.lease["options"]
            dhcp_flags = dhcp.flags.UNICAST
            if dhcp.options.ROUTER in self.lease["options"]:
                default_routers = self.lease["options"][dhcp.options.ROUTER]
            request_options = {
                dhcp.options.REQUESTED_IP_ADDRESS: expected_dest_ip,
                dhcp.options.SERVER_IDENTIFIER:    expected_server_identifier,
                dhcp.options.PARAMETER_REQUEST_LIST: [
                    dhcp.options.SUBNET_MASK,
                    dhcp.options.ROUTER,
                    dhcp.options.DOMAIN_SERVER
                ]
            }
        stdout.writeline(
            "{0} ip {1}".format(state_name, expected_yip),
            prefix=self.name
        )
        stdout.writeline("{0} parameters SUBNET_MASK ROUTER DOMAIN_SERVER".format(state_name), prefix=self.name)
        stdout.writeline(
            "{0} from server {1}".format(state_name, expected_server_identifier),
            prefix=self.name
        )
        # Send out the DHCP Request
        try:
            dhcp.send(
                mtype=dhcp.message_types.REQUEST,
                hops=0,
                htype=self.htype,
                xid=self.xid,
                dhcp_flags=dhcp_flags,
                source_ip=expected_yip,
                dest_ip=expected_server_identifier,
                secs=int(time.time()) - self.starttime,
                chaddr=self.chaddr,
                cip=expected_dest_ip,
                dest_haddr=shaddr,
                raw_channel=self.channel,
                dhcp_options=request_options,
                nicname=self.interface_name
            )
        except dhcp.error as err:
            stderr.writeline(err)
            self.state = states.EXITING
            return
        # Generator to get DHCP Acks
        dhcp_acks = dhcp.receive(
            mtypes=[dhcp.message_types.ACK, dhcp.message_types.NACK],
            expected_chaddr=self.chaddr,
            expected_xid=self.xid,
            raw_channel=self.channel,
            end_time=end_time,
            expected_dest_ip=expected_dest_ip,
            expected_server_identifier=expected_server_identifier,
            nicname=self.interface_name
        )
        # Process the Acknowledgements
        for dhcp_ack in dhcp_acks:
            # Check for a DHCP ACK to Bind
            if dhcp_ack["message_type"] == dhcp.message_types.ACK:
                # Validate that the DHCP ACK Acknowledges a DHCP Request
                if dhcp.options.IP_ADDRESS_LEASE_TIME not in dhcp_ack["options"]:
                    continue
                # Check if DHCP ACK matches Offer
                if (dhcp_ack["yip"] != expected_yip):
                    continue
                # Accept the Offer
                stdout.writeline(
                    "ack from ip {0}".format(dhcp_ack["source_ip"]),
                    prefix=self.name
                )
                stdout.writeline(
                    "ack ip {0}".format(dhcp_ack["yip"]),
                    prefix=self.name
                )
                subnet_mask = dhcp_ack["options"][dhcp.options.SUBNET_MASK]
                # Special case where Gateway isn't supplied, we take the first ip of the subnet as gateway
                if dhcp.options.ROUTER not in dhcp_ack["options"]:
                    if default_routers is None:
                        dhcp_ack["options"][dhcp.options.ROUTER] = [network_types.decoders.ip(network_types.encoders.uint32((
                            network_types.decoders.uint32(network_types.encoders.ip(expected_yip)) &
                            network_types.decoders.uint32(network_types.encoders.ip(subnet_mask))
                            ) + 1))]
                    else:
                        dhcp_ack["options"][dhcp.options.ROUTER] = default_routers
                stdout.writeline(
                    "ack params SUBNET_MASK={0} ROUTER={1} DOMAIN_SERVER={2}".format(
                        dhcp_ack["options"][dhcp.options.SUBNET_MASK],
                        dhcp_ack["options"][dhcp.options.ROUTER],
                        dhcp_ack["options"][dhcp.options.DOMAIN_SERVER]
                    ),
                    prefix=self.name
                )
                self.lease = client._get_lease(
                    self.interface_name,
                    expected_yip,
                    expected_server_identifier,
                    sname,
                    shaddr,
                    options,
                    dhcp_ack,
                    self.lease_file
                )
                self.state = states.BOUND
                stdout.writeline("BOUND", prefix=self.name)
                stdout.write_named_dict("DHCP Lease", self.lease, prefix=self.name)
                self.do_event_callbacks()
                return
            # Check for DHCP NACK to Reject
            elif dhcp_ack["message_type"] == dhcp.message_types.NACK:
                # Reject the offer
                stdout.writeline(
                    "nack from ip {0}".format(dhcp_ack["source_ip"]),
                    prefix=self.name
                )
                stdout.writeline(
                    "nack ip {0}".format(expected_yip),
                    prefix=self.name
                )
                # Go back to INIT
                self.state = states.INIT
                return

    def requesting(self, end_time):
        """
        DHCP Client Requesting State

        - Request on an offer and bind to it if an acknowledgement is returned.
        """
        self.request_and_bind(end_time)
        if self.state == states.REQUESTING:
            self.state = states.SELECTING

    def bound(self, end_time):
        """
        DHCP Client Bound State

        - If the renewal time has elapsed, move to the renewing state, else do nothing.
        """
        # Check if Lease has expired
        if int(time.time()) > self.lease["renew"]:
            self.state = states.RENEWING

    def renewing(self, end_time):
        """
        DHCP Client Renewing State

        - If the rebinding time has elapsed, move to the rebinding state.
        - Else, try to renew the lease by sending a dhcp request and wait for an ACK.
        - If ACK is recieved, go to bound.
        - If no ACK is recieved, do nothing.
        - If a NACK is recieved, then go to INIT.
        """
        # Check if Lease has expired
        if int(time.time()) > self.lease["rebind"]:
            self.state = states.REBINDING
        else:
            self.request_and_bind(end_time)

    def rebinding(self, end_time):
        """
        DHCP Client Rebinding State

        - If the expired time has elapsed, go to the INIT state.
        - Else, try to renew the lease by sending a dhcp request and wait for an ACK.
        - If ACK is recieved, go to bound.
        - If no ACK is recieved, do nothing.
        - If a NACK is recieved, then go to INIT.
        """
        # Check if Lease has expired
        if int(time.time()) > self.lease["expire"]:
            self.state = states.INIT
        else:
            self.request_and_bind(end_time)

    def rebooting(self, end_time):
        """
        DHCP Client Rebinding State

        - If the expired time has elapsed, go to the INIT state.
        - Else, try to renew the lease by sending a dhcp request and wait for an ACK.
        - If ACK is recieved, go to bound.
        - If no ACK is recieved, send a DHCPRelease and go to init
        - If NACK is recieved, go to INIT.
        """
        # Check if Lease has expired
        if int(time.time()) > self.lease["expire"]:
            self.state = states.INIT
        else:
            self.request_and_bind(end_time)
            if self.state != states.BOUND:
                # Send a DHCP Release and go to INIT
                stdout.writeline("dhcp releasing {0}".format(self.lease["ip"]), prefix=self.name)
                request_options = {dhcp.options.SERVER_IDENTIFIER: self.lease["dhcp_server"]["ip"]}
                try:
                    dhcp.send(
                        mtype=dhcp.message_types.RELEASE,
                        hops=0,
                        htype=self.htype,
                        xid=self.xid,
                        dhcp_flags=dhcp.flags.UNICAST,
                        secs=0,
                        chaddr=self.chaddr,
                        cip=self.lease["ip"],
                        dhcp_options=request_options,
                        raw_channel=self.channel,
                        dest_haddr=self.lease["dhcp_server"]["mac_address"],
                        dest_ip=self.lease["dhcp_server"]["ip"],
                        nicname=self.interface_name
                    )
                except dhcp.error as err:
                    stderr.writeline(err)
                self.state = states.INIT

    def exiting(self, end_time):
        """
        DHCP Client Exiting State

        - Release any existing leases.
        - Remove the lease file.
        - Go to the SHUT_DOWN state
        """
        if self.lease:
            stdout.writeline("dhcp releasing {0}".format(self.lease["ip"]), prefix=self.name)
            request_options = {dhcp.options.SERVER_IDENTIFIER: self.lease["dhcp_server"]["ip"]}
            try:
                dhcp.send(
                    mtype=dhcp.message_types.RELEASE,
                    hops=0,
                    htype=self.htype,
                    xid=self.xid,
                    dhcp_flags=dhcp.flags.UNICAST,
                    secs=0,
                    chaddr=self.chaddr,
                    cip=self.lease["ip"],
                    dhcp_options=request_options,
                    raw_channel=self.channel,
                    dest_haddr=self.lease["dhcp_server"]["mac_address"],
                    dest_ip=self.lease["dhcp_server"]["ip"],
                    nicname=self.interface_name
                )
            except dhcp.error as err:
                stderr.writeline(err)
        if os.path.isfile(self.lease_file):
            os.remove(self.lease_file)
        self.lease = None
        self.state = states.SHUT_DOWN
        self.do_event_callbacks()

    def init_reboot(self, leases):
        """
        DHCP Client Reboot State

        - Validate any existing leases.
        - If the lease is still valid, rebind.
        - Else go to the INIT state.
        """
        # Validate the leases
        for lease in leases:
            stdout.write_named_dict("loaded lease", lease)
            missing_keys = {"interface", "ip", "subnet_mask", "gateways", "dhcp_server", "options", "renew", "rebind",
                            "expire"} - lease.keys()
            if missing_keys:
                stdout.writeline(
                    "skipping lease, missing keys {0}".format(missing_keys),
                    prefix=self.name
                )
                continue
            if not network_types.validaters.ip(lease["ip"]):
                stdout.writeline(
                    "skipping lease, leased ip {0} is not a valid ip".format(lease["ip"]),
                    prefix=self.name
                )
                continue
            if not network_types.validaters.ip(lease["subnet_mask"]):
                stdout.writeline(
                    "skipping lease, subnet {0} is not a valid ip".format(lease["subnet_mask"]),
                    prefix=self.name
                )
                continue
            if not network_types.validaters.iplist(lease["gateways"]):
                stdout.writeline(
                    "skipping lease, gateway ips {0} are not/not all valid ips".format(lease["gateways"]),
                    prefix=self.name
                )
                continue
            if not isinstance(lease["dhcp_server"], dict):
                stdout.writeline(
                    "skipping lease, dhcp server info {0} is invalid".format(lease["dhcp_server"]),
                    prefix=self.name
                )
                continue
            missing_keys = {"ip", "name", "mac_address"} - lease["dhcp_server"].keys()
            if missing_keys:
                stdout.writeline(
                    "skipping lease, dhcp server info is missing keys {0}".format(missing_keys),
                    prefix=self.name
                )
                continue
            if not network_types.validaters.ip(lease["dhcp_server"]["ip"]):
                stdout.writeline(
                    "skipping lease, dhcp server ip {0} is not a valid ip".format(lease["dhcp_server"]["ip"]),
                    prefix=self.name
                )
                continue
            if not network_types.validaters.cstring(lease["dhcp_server"]["name"]):
                stdout.writeline(
                    "skipping lease, dhcp server name {0} is invalid".format(lease["dhcp_server"]["name"]),
                    prefix=self.name
                )
                continue
            if not network_types.validaters.ethermac(lease["dhcp_server"]["mac_address"]):
                stdout.writeline(
                    "skipping lease, dhcp server hwaddr {0} is invalid".format(lease["dhcp_server"]["mac_address"]),
                    prefix=self.name
                )
                continue
            if not isinstance(lease["options"], dict):
                stdout.writeline(
                    "skipping lease, dhcp options field is invalid",
                    prefix=self.name
                )
                continue
            try:
                list([int(option_type) for option_type in lease["options"]])
            except Exception:
                stdout.writeline(
                    "skipping lease, dhcp options field ids are invalid",
                    prefix=self.name
                )
                continue
            lease["options"] = {int(k): v for k, v in lease["options"].items()}
            for option_type, option_value in lease["options"].items():
                if option_type in dhcp.options.lookup:
                    if not getattr(network_types.validaters, dhcp.options.lookup[option_type][2])(option_value):
                        stdout.writeline(
                            "skipping lease, option {0} value is invalid".format(dhcp.options.lookup[option_type][0]),
                            prefix=self.name
                        )
                        continue
            if not network_types.validaters.uint64(lease["renew"]):
                stdout.writeline(
                    "skipping lease, renewal time {0} is invalid".format(lease["renew"]),
                    prefix=self.name
                )
                continue
            if not network_types.validaters.uint64(lease["rebind"]):
                stdout.writeline(
                    "skipping lease, rebinding time {0} is invalid".format(lease["rebind"]),
                    prefix=self.name
                )
                continue
            if not network_types.validaters.uint64(lease["expire"]):
                stdout.writeline(
                    "skipping lease, expiry time {0} is invalid".format(lease["expire"]),
                    prefix=self.name
                )
                continue
            # Lease is valid, select it
            self.lease = lease
            stdout.writeline(
                "selected lease for renewal",
                prefix=self.name
            )
            break
        # Select the next state
        if (self.lease is None) or (int(time.time()) > self.lease["expire"]):
            self.state = states.INIT
        elif int(time.time()) > self.lease["rebind"]:
            self.state = states.REBINDING
        elif int(time.time()) > self.lease["renew"]:
            self.state = states.RENEWING
        else:
            self.state = states.REBOOTING

    def run(self):
        """
        DHCP Daemon event loop
        """
        while self.state != states.SHUT_DOWN:
            end_time = int(time.time()) + 32
            state_name = states.lookup[self.state]
            # Open a Broadcast Channel
            if self.state not in [states.BOUND, states.SHUT_DOWN]:
                self.channel = dhcp.open_raw_client_channel(self.interface_name, end_time-int(time.time()))
            # Check if in transition state by error
            if self.state in [states.INIT_REBOOT]:
                raise Exception("DHCP Client hung in a transition state: {0}".format(state_name))
            # Run the state
            if self.state is not states.SHUT_DOWN:
                getattr(self, state_name)(end_time)
            # Wait till end time
            cur_time = int(time.time())
            if self.state in [states.BOUND, states.SHUT_DOWN]:
                if cur_time < end_time:
                    time.sleep(end_time - cur_time)
        self.thread = None

    def start(self):
        """
        Start the DHCP client
        """
        if self.state == states.SHUT_DOWN:
            self.state = states.BOOT

    def stop(self):
        """
        Halt the DHCP client
        """
        if self.state != states.SHUT_DOWN:
            self.state = states.EXITING

    def kill(self):
        """
        Kill the DHCP Client
        """
        self.exiting(0)

    def is_running(self):
        """
        Return true if the daemon is running, false otherwise
        """
        if not self.thread:
            return False
        else:
            return self.thread.is_alive()

    def stopped_gracefully(self):
        sg = True
        if self.thread:
            if self.thread.is_alive():
                # Thread hasn't stopped
                sg = False
            elif self.state != states.SHUT_DOWN:
                # Thread died in a state other than SHUT_DOWN
                sg = False
        return sg
