from scapy.all import *
import argparse

"""
Script that emulates the Cisco command suppress-fa on OSPFv2

The OSPF Forwarding Address Suppression in Translated Type-5 LSAs feature causes
an NSSA ABR to translate Type-7 LSAs to Type-5 LSAs, but use the 0.0.0.0 as the 
forwarding address instead of that specified in the Type-7 LSA
	
This feature causes the router to be noncompliant with RFC 1587

In short, if routers do not have the knowledge on how to reach the forwarding address,
due to some kind of lsa filtering, you can suppress the FA route advertisement and suppress 
this value, this would results that the FA be equal to 0.0.0.0 which forces the use of 
the ASBR to reach the destination.

Link:
	https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/configuration/15-mt/iro-15-mt-book/iro-for-add-sup.html
"""

OSPF_NUM_LSA_LEN = 4


def ospf_lsa_checksum(lsa):
    """ 
	The LS checksum is computed over the entire contents of the LSA, excepting the
	LS age field. This is left out so that the LSAs age can be incremented without 
	updating the LS checksum
	"""
    return fletcher16_checkbytes(b"\x00\x00" + lsa[2:], 16)  # leave out age


def suppress_fa(packet, new_vlan, router, suppress):
    # packet is an IP packet, the fwd address will be suppressed only in OSPFv2 LSA Type 5
    if packet.haslayer(Dot1Q):
        # Translate the vlan
        packet[Dot1Q].vlan = new_vlan
        if packet.haslayer(IP):
            if packet.haslayer(OSPFv3_Hdr):
                pass
            # Check Protocol = 89 (OSFP) or using scapy OSPF extension
            if packet.haslayer(OSPF_Hdr):
                header = bytes(packet.getlayer(OSPF_Hdr))
                ospf_type = header[1]
                ospf_len = int.from_bytes(header[3:4], "big")
                # print("OSPF packet type: %x" % ospf_type)
                # print("OSPF packet len: %d" % ospf_len)

                # Check if this is an OSPF LSA update
                if ospf_type == 0x04:
                    # Packet will be crafted
                    # Remove both checksums so scapy will compute them
                    del packet[IP].chksum
                    del packet[OSPF_Hdr].chksum

                    # OSPF_LSA_UPDATE = NUM_LSA(4 bytes) + LSA_1 + LSA_2 + etc...
                    b = bytes(packet.getlayer(OSPF_LSUpd))
                    lsa = b
                    # Check the number of LSAs
                    num_lsa = int.from_bytes(lsa[:OSPF_NUM_LSA_LEN], "big")
                    print("OSPF number of LSAs: %d" % num_lsa)

                    # Iterate over each LSA
                    lsa = lsa[OSPF_NUM_LSA_LEN:]
                    bindex = OSPF_NUM_LSA_LEN
                    for x in range(0, num_lsa):
                        lsa_type = lsa[3]
                        lsa_len = int.from_bytes(lsa[18:20], "big")
                        if lsa_type == 5:
                            # options (3 byte) lsa[0:2]
                            # lsa type (1 byte) lsa[3]
                            # link state id (4 bytes) lsa[4:7]
                            linkid = "%s.%s.%s.%s" % (lsa[4], lsa[5], lsa[6], lsa[7])
                            # adv router (4 bytes) lsa[8:11]
                            advrouter = "%s.%s.%s.%s" % (
                                lsa[8],
                                lsa[9],
                                lsa[10],
                                lsa[11],
                            )
                            # seq number (4 bytes) lsa[12:15]
                            # checksum (2 bytes) lsa[16:17]
                            # len (2 bytes) lsa[18:19]
                            netmask = "%s.%s.%s.%s" % (
                                lsa[20],
                                lsa[21],
                                lsa[22],
                                lsa[23],
                            )
                            # metric type (1 byte) lsa[24]
                            # metric (3 bytes) lsa[25:27]
                            fwd_address = "%s.%s.%s.%s" % (
                                lsa[28],
                                lsa[29],
                                lsa[30],
                                lsa[31],
                            )
                            route_tag = "%s.%s.%s.%s" % (
                                lsa[32],
                                lsa[33],
                                lsa[34],
                                lsa[35],
                            )
                            print("OSPF LSA number: %d of %d" % ((x + 1), num_lsa))
                            print(" OSPF LSA type: %d" % lsa_type)
                            print(" OSPF LSA len: %d" % lsa_len)
                            print(" lsa link id: %s" % linkid)
                            print(" advertising router: %s" % advrouter)
                            print(" fwd address: %s" % fwd_address)

                            # Check if we need to suppress fwd address
                            if router != "0.0.0.0":
                                if router != advrouter:
                                    # Disable LSA suppression if the Adv routers do not match
                                    if suppress == True:
                                        print(
                                            " >>>> Do not change FA address to 0 (%s != %s)"
                                            % (router, advrouter)
                                        )
                                    suppress = False

                            # Suppress fwd address for the current LSA
                            if suppress:
                                if packet.haslayer(OSPF_LSUpd):
                                    ospf_payload = list(bytes(packet.getlayer(OSPF_LSUpd)))
                                else:
                                    ospf_payload = list(bytes(packet.getlayer(Raw)))
                                print(" >>>> Changing FA address to 0")
                                ospf_payload[bindex + 28] = 0
                                ospf_payload[bindex + 29] = 0
                                ospf_payload[bindex + 30] = 0
                                ospf_payload[bindex + 31] = 0

                                # Compute checksum for current LSA
                                # As we are using raw, scapy will not compute it
                                aa, bb = ospf_lsa_checksum(bytes(ospf_payload[bindex:]))
                                ospf_payload[bindex + 16] = aa
                                ospf_payload[bindex + 17] = bb

                                # Restablish the modified payload
                                packet[OSPF_Hdr].remove_payload()
                                packet = packet / Raw(load=bytes(ospf_payload))
                                packet.show()

                        # Process next LSA
                        lsa = lsa[lsa_len:]
                        bindex = bindex + lsa_len

    return packet


def pkt_callback(pkt):

    # Example arguments: --vlans 1 2 --vlans 3 4
    # Example vlans: [[1, 2], [3, 4]]
    if pkt.haslayer(Dot1Q):
        print("VLAN ID: " + str(pkt[Dot1Q].vlan))
        vlan = pkt[Dot1Q].vlan
        for pos, sub_list in enumerate(args.vlans):
            try:
                pos2 = sub_list.index(vlan)
                # Toggle the position pos2 to find its translation vlan
                pos2 = 1 - pos2
                new_vlan = sub_list[pos2]
                newpkt = suppress_fa(pkt, new_vlan, args.advrouter, args.suppress)
                # Send packet at layer 2
                sendp(newpkt, iface=args.interface, verbose=1)
            except ValueError:
                pass
        # vlan does not need to be translated
    return


def ipaddress(ip):
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(
            0 < len(part) < 4 and 0 <= int(part) < 256 for part in parts
        )
    except (AttributeError, TypeError, ValueError):
        # `ip` isn't even a string
        # one of the 'parts' not convertible to integer
        msg = "Not a valid ip address: '{0}'.".format(ip)
        raise argparse.ArgumentTypeError(msg)


if __name__ == "__main__":
    load_contrib("ospf")

    parser = argparse.ArgumentParser()
    # The vlans argument can be repeated multiple times providing the pair of vlans to be translated
    parser.add_argument(
        "--vlans",
        type=int,
        required=True,
        nargs=2,
        action="append",
        help="define the pair of vlans to be translated",
    )
    parser.add_argument(
    	"-i",
        "--interface",
        type=str,
        required=True,
        help="interface used to capture/send the packet",
    )
    # FIXME: Control type for ipaddress
    parser.add_argument(
        "--advrouter",
        dest="advrouter",
        type=str,
        default="0.0.0.0",
        required=False,
        help="Match on the advertising router ip address",
    )
    parser.add_argument(
        "--suppress",
        dest="suppress",
        default=False,
        required=False,
        action="store_true",
        help="Suppress-fa in OSPF LSA type 5",
    )
    args = parser.parse_args()

    # store=0 says not to store any packet received and prn says send the packet to callback
    # FIXME: arguments for callback pkt_cabllback
    sniff(
        iface=args.interface,
        prn=pkt_callback,
        filter="vlan",
        store=0,
    )
