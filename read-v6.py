from scapy.all import *
from scapy.utils import fletcher16_checkbytes, checksum
import pprint
import ipaddress

OSPF_NUM_LSA_LEN = 4

'''
Useful scapy commands
    print(packet.layers())
'''

# Read from file first to test a few things

# Dissect an OSPF packet
load_contrib('ospf')

#packets = rdpcap('lsa5.cap')
packets = rdpcap('ospf3-single-type5.cap')
for packet in packets:
    if packet.haslayer(Dot1Q):
        if packet.haslayer(IP):
            # Check Protocol = 89 (OSFP)
            if packet.haslayer(OSPF_Hdr):
                header = bytes(packet.getlayer(OSPF_Hdr))
                ospf_type = header[1]
                ospf_len = int.from_bytes(header[3:4], 'big')
                print("OSPF type: %x" % ospf_type)
                print("OSPF packet len: %d" % ospf_len)
                # Need to remove the checksum so scapy will update it
                del packet[IP].chksum
                del packet[OSPF_Hdr].chksum
        elif packet.haslayer(IPv6):
            # Check Protocol = 89 (OSFP)
            if packet.haslayer(OSPFv3_Hdr):
                header = bytes(packet.getlayer(OSPFv3_Hdr))
                ospf_type = header[1]
                ospf_len = int.from_bytes(header[3:4], 'big')
                print("OSPF type: %x" % ospf_type)
                print("OSPF packet len: %d" % ospf_len)
                # Need to remove the checksum so scapy will update it
                del packet[IPv6].chksum
                del packet[OSPFv3_Hdr].chksum

        # Check if this is an LSA update in the OSPF header
        if ospf_type == 0x04:
            # Check the number of LSAs
            # OSPF_LSA_UPDATE = NUM_LSA(4 bytes) + LSA_1 + LSA_2 + etc...
            if packet.haslayer(OSPF_LSUpd):
                b = bytes(packet.getlayer(OSPF_LSUpd))
            elif packet.haslayer(OSPFv3_LSUpd):
                b = bytes(packet.getlayer(OSPFv3_LSUpd))

            lsa = b
            num_lsa = int.from_bytes(lsa[:OSPF_NUM_LSA_LEN], 'big')
            print("OSPF number of LSAs: %d" % num_lsa)
            
            # Iterate over each LSA
            lsa = lsa[OSPF_NUM_LSA_LEN:]
            bindex = OSPF_NUM_LSA_LEN
            for x in range(0,num_lsa):
                #lsa_type = int.from_bytes(lsa[2:3], 'big') >> 4
                lsa_type = lsa[3]
                print("%x" % lsa_type)
                lsa_len = int.from_bytes(lsa[18:20], 'big')
                print("OSPF LSA number: %d" % (x+1))
                print("OSPF LSA type: %d" % lsa_type)
                print("OSPF LSA len: %d" % lsa_len)
                # IPv4
                if lsa_type == 5 and packet.haslayer(OSPF_LSUpd):
                    # options (3 byte) lsa[0:2]
                    # lsa type (1 byte) lsa[3]
                    # link state id (4 bytes) lsa[4:7]
                    # adv router (4 bytes) lsa[8:11]
                    advrouter = "%s.%s.%s.%s" % (lsa[8],lsa[9],lsa[10],lsa[11])
                    # seq number (4 bytes) lsa[12:15]
                    # checksum (2 bytes) lsa[16:17]
                    # len (2 bytes) lsa[18:19]
                    netmask = "%s.%s.%s.%s" % (lsa[20],lsa[21],lsa[22],lsa[23])
                    # metric type (1 byte) lsa[24]
                    # metric (3 bytes) lsa[25:27]
                    fwd_address = "%s.%s.%s.%s" % (lsa[28],lsa[29],lsa[30],lsa[31])
                    route_tag = "%s.%s.%s.%s" % (lsa[32],lsa[33],lsa[34],lsa[35])
                    print("advertising router: %s" % advrouter)
                    print("fwd address: %s" % fwd_address)

                    # Suppress Forwarding address from the lsa
                    if packet.haslayer(OSPF_LSUpd):
                        ospf_payload = list(bytes(packet.getlayer(OSPF_LSUpd)))
                    else:
                        ospf_payload = list(bytes(packet.getlayer(Raw)))
                    ospf_payload[bindex + 28] = 0
                    ospf_payload[bindex + 29] = 0
                    ospf_payload[bindex + 30] = 0
                    ospf_payload[bindex + 31] = 0

                    # Compute checksum for current LSA
                    aa,bb = ospf_lsa_checksum(bytes(ospf_payload[bindex:]))
                    ospf_payload[bindex + 16] = aa
                    ospf_payload[bindex + 17] = bb

                    # Restablish the modified payload
                    packet[OSPF_Hdr].remove_payload()
                    packet = packet / Raw(load=bytes(ospf_payload))
                    
                    # Send the LSA update
                    sendp(packet, iface="br0")          
                # IPv4
                elif lsa_type == 5 and packet.haslayer(OSPFv3_LSUpd):
                    # options (2 byte) lsa[0:1]
                    # lsa type (2 byte) lsa[2:3]
                    # link state id (4 bytes) lsa[4:7]
                    # adv router (4 bytes) lsa[8:11]
                    advrouter = "%s.%s.%s.%s" % (lsa[8],lsa[9],lsa[10],lsa[11])
                    # seq number (4 bytes) lsa[12:15]
                    # checksum (2 bytes) lsa[16:17]
                    # len (2 bytes) lsa[18:19]
                    # flags (1 byte) lsa[20]
                    # metric type (3 byte) lsa[21:23]
                    # prefix length (1 byte) lsa[24]
                    # prefix options length (1 byte) lsa[25]
                    # referenced ls type (2 bytes) lsa[26:27]
                    # Address prefix (16 bytes) lsa[28:43]
                    # Fwd address (16 bytes) lsa[44:59]
                    prefix = ipaddress.IPv6Address(lsa[28:44])
                    print(prefix)
                    fwd = ipaddress.IPv6Address(lsa[44:60])
                    print(fwd)

                    # Suppress Forwarding address from the lsa
                    if packet.haslayer(OSPFv3_LSUpd):
                        ospf_payload = list(bytes(packet.getlayer(OSPFv3_LSUpd)))
                        print("OSPFv3_LSUpd")
                    else:
                        ospf_payload = list(bytes(packet.getlayer(Raw)))
                        print("Raw")
   
                    for x in range(bindex + 44, bindex + 44 + 16, 1):
                        ospf_payload[x] = 0

                    # Compute checksum for current LSA
                    aa,bb = ospf_lsa_checksum(bytes(ospf_payload[bindex:]))
                    ospf_payload[bindex + 16] = aa
                    ospf_payload[bindex + 17] = bb

                    # Restablish the modified payload
                    packet[OSPFv3_Hdr].remove_payload()
                    packet = packet / Raw(load=bytes(ospf_payload))
                    
                    # Send the LSA update
                    sendp(packet, iface="br0")          

                # Move forward
                lsa = lsa[lsa_len:]
                bindex = bindex + lsa_len
