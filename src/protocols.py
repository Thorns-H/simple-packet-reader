from src.helpers import decimal_to_hexa, binary_to_decimal, byte_binary
from src.helpers import get_oui_nic, CLEAR
from src.helpers import reformat_ipv6
import os

global BYTES
BYTES = 0

def arp_frame(packet : list):

    HTYPE = decimal_to_hexa(packet[:2])
    HTYPE = f'{HTYPE[0]}{HTYPE[1]}'

    PTYPE = decimal_to_hexa(packet[2:4])
    PTYPE = f'0x{PTYPE[0]}{PTYPE[1]}'

    HARDWARE_ADDR_LEN = packet[4]
    PROTOCOL_ADDR_LEN = packet[5]

    OP_CODE = decimal_to_hexa(packet[6:8])
    OP_CODE = f'{OP_CODE[0]}{OP_CODE[1]}'

    GET_SOURCE_ADDR = decimal_to_hexa(packet[8:8 + HARDWARE_ADDR_LEN])

    SOURCE_ADDR = ''

    for byte in GET_SOURCE_ADDR:
        SOURCE_ADDR = f'{SOURCE_ADDR}{byte}:'

    SOURCE_ADDR = SOURCE_ADDR[:-1]

    GET_SOURCE_PROTOCOL_ADDR = packet[8 + HARDWARE_ADDR_LEN:8 + 4 + HARDWARE_ADDR_LEN]

    SOURCE_PROTOCOL_ADDR = ''

    for byte in GET_SOURCE_PROTOCOL_ADDR:
        SOURCE_PROTOCOL_ADDR = f'{SOURCE_PROTOCOL_ADDR}{byte}.'

    SOURCE_PROTOCOL_ADDR = SOURCE_PROTOCOL_ADDR[:-1]

    GET_TARGET = decimal_to_hexa(packet[8 + 4 + HARDWARE_ADDR_LEN:8 + 4 + HARDWARE_ADDR_LEN + HARDWARE_ADDR_LEN])

    TARGET = ''

    for byte in GET_TARGET:
        TARGET = f'{TARGET}{byte}:'

    TARGET = TARGET[:-1]

    GET_TARGET_PROTOCOL_ADDR = packet[8 + 4 + HARDWARE_ADDR_LEN + HARDWARE_ADDR_LEN:8 + 4 + HARDWARE_ADDR_LEN + HARDWARE_ADDR_LEN + 4]

    TARGET_PROTOCOL_ADDR = ''

    for byte in GET_TARGET_PROTOCOL_ADDR:
        TARGET_PROTOCOL_ADDR = f'{TARGET_PROTOCOL_ADDR}{byte}.'

    TARGET_PROTOCOL_ADDR = TARGET_PROTOCOL_ADDR[:-1]

    ARP_HEADER = "\033[1m" + "[ARP]" + "\033[0m"

    print(f'\n\t\t     {ARP_HEADER}\n')

    if HTYPE == '0001':
        print(f'     - Hardware Type: Ethernet (1)')
    if PTYPE == '0x0800':
        print(f'     - Protocol Type: {PTYPE} (Ipv4)')

    print(f'     - Hardware Address Length: {HARDWARE_ADDR_LEN} bytes')
    print(f'     - Protocol Address Length: {PROTOCOL_ADDR_LEN} bytes')

    if OP_CODE == '0000':
        print(f'     - Operation: ARP Reserved (0)')
    elif OP_CODE == '0001':
        print(f'     - Operation: ARP Request (1)')
    elif OP_CODE == '0002':
        print(f'     - Operation: ARP Reply (2)')
    elif OP_CODE == '0003':
        print(f'     - Operation: ARP Request - Reverse (3)')
    elif OP_CODE == '0004':
        print(f'     - Operation: ARP Reply - Reverse (4)')

    print(f'     - Sender MAC Address: {SOURCE_ADDR}')
    print(f'     - Sender IP Address: {SOURCE_PROTOCOL_ADDR}')
    print(f'     - Target MAC Address: {TARGET}')
    print(f'     - Target IP Address: {TARGET_PROTOCOL_ADDR}')

    input('\t\n')

def ipv4_frame(packet : list, icmp : bool):

    GET_VERSION_IHL = byte_binary(packet[0])
    VERSION = GET_VERSION_IHL[:4]
    IHL = GET_VERSION_IHL[4:]
    IHL = binary_to_decimal(int(IHL))

    GET_DSCP_ECN = byte_binary(packet[1])
    DSCP = GET_DSCP_ECN[:6]
    ECN = GET_DSCP_ECN[6:]

    TOTAL_LENGTH = packet[2:4]
    TOTAL_LENGTH = f'{str(byte_binary(TOTAL_LENGTH[0]))}{str(byte_binary(TOTAL_LENGTH[1]))}'
    TOTAL_LENGTH = binary_to_decimal(int(TOTAL_LENGTH))

    IDENTIFICATION = packet[4:6]
    IDENTIFICATION = f'{str(byte_binary(IDENTIFICATION[0]))}{str(byte_binary(IDENTIFICATION[1]))}'
    IDENTIFICATION = binary_to_decimal(int(IDENTIFICATION))

    GET_FLAGS = byte_binary(packet[6])
    FLAGS = GET_FLAGS[:3]
    GET_OFFSET = byte_binary(packet[7])
    OFFSET = int(f'{GET_FLAGS[-3:]}{GET_OFFSET}')
    TTL = packet[8]
    PROTOCOL = packet[9]
    HEADER_CHECKSUM = decimal_to_hexa(packet[10:12])
    SENDER_ADDR = packet[12:16]
    DEST_ADDR = packet[16:20]

    IPV4_HEADER = "\033[1m" + "[IPV4]" + "\033[0m"

    print(f'\n\t\t     {IPV4_HEADER}\n')

    if VERSION == '0100':
        print(f'     -> Version: Ipv4 (4)')
    print(f'     -> Internet Header Length (IHL): {IHL}')
    print(f'        - {str((IHL*32)/8)[:2]} bytes in total')

    print(f"\n     -> Type of Service (TOS): {packet[1]}")

    if DSCP == '000000':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - CS0')
    elif DSCP == '001000':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - CS1')
    elif DSCP == '010000':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - CS2')
    elif DSCP == '011000':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - CS3')
    elif DSCP == '100000':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - CS4')
    elif DSCP == '101000':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - CS5')
    elif DSCP == '110000':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - CS6')
    elif DSCP == '111000':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - CS7')
    elif DSCP == '001010':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF11')
    elif DSCP == '001100':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF12')
    elif DSCP == '001110':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF13')
    elif DSCP == '010010':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF21')
    elif DSCP == '010100':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF22')
    elif DSCP == '010110':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF23')
    elif DSCP == '011010':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF31')
    elif DSCP == '011100':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF32')
    elif DSCP == '011110':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF33')
    elif DSCP == '100010':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF41')
    elif DSCP == '100100':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF42')
    elif DSCP == '100110':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - AF43')
    elif DSCP == '101110':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - EF')
    elif DSCP == '101100':
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard) - VOICE-ADMIT')

    if ECN == '00':
        print(f'        - Explicit Congestion Notification: {binary_to_decimal(int(ECN))} (Non-ETC)')
    elif ECN == '01':
        print(f'        - Explicit Congestion Notification: {binary_to_decimal(int(ECN))} (ECN Capable Transport - 1)')
    elif ECN == '10':
        print(f'        - Explicit Congestion Notification: {binary_to_decimal(int(ECN))} (ECN Capable Transport - 2)')
    elif ECN == '11':
        print(f'        - Explicit Congestion Notification: {binary_to_decimal(int(ECN))} (CE - Congestion Experienced)')

    print(f'     -> Total Length: {TOTAL_LENGTH} bytes')
    print(f'     -> Identification: {IDENTIFICATION}')

    print(f'\n     -> Flags: {FLAGS}')

    if FLAGS[0] == '0':
        print(f"        - Reserved: {FLAGS[0]}")
    if FLAGS[1] == '1':
        print(f"        - Don't Fragment: {FLAGS[1]} (True)")
    else:
        print(f"        - Don't Fragment: {FLAGS[1]} (False)")

    if FLAGS[2] == '1':
        print(f"        - More Fragments: {FLAGS[2]} (True)")
    else:
        print(f"        - More Fragments: {FLAGS[2]} (False)")

    print(f'     -> Fragment Offset: {OFFSET}')

    print(f'\n     -> Time to Live (TTL): {TTL} hops')

    if PROTOCOL == 1:
        print(f'     -> Protocol: {PROTOCOL} (ICMP)')
        print(f"        - Internet Control Message Protocol")
    elif PROTOCOL == 6:
        print(f'     -> Protocol: {PROTOCOL} (TCP)')
        print(f"        - Transmission Control Protocol")
    elif PROTOCOL == 17:
        print(f'     -> Protocol: {PROTOCOL} (UDP)')
        print(f"        - User Datagram Protocol")
    
    print(f'\n     -> FCS: 0x {HEADER_CHECKSUM[0]} {HEADER_CHECKSUM[1]}')
    print(f'     -> Source Address: {SENDER_ADDR[0]}.{SENDER_ADDR[1]}.{SENDER_ADDR[2]}.{SENDER_ADDR[3]}')
    print(f'     -> Destination Address: {DEST_ADDR[0]}.{DEST_ADDR[1]}.{DEST_ADDR[2]}.{DEST_ADDR[3]}')

    if PROTOCOL == 1 and icmp:
        icmpv4(packet[20:])
    else:
        input('\n\t')

def icmpv4(packet : list):
    
    TYPE = packet[0]
    CODE = packet[1]
    CHECK_SUM = decimal_to_hexa(packet[2:4])
    IDENTIFIER = binary_to_decimal(int(f'{byte_binary(packet[4])}{byte_binary(packet[5])}'))
    SEQUENCE_NUM = binary_to_decimal(int(f'{byte_binary(packet[6])}{byte_binary(packet[7])}'))

    GET_GATEWAY = packet[4:8]
    GATEWAY = ''
    GET_ORIGINAL_DATA = packet[8:20]

    ICMP_HEADER = "\033[1m" + "[ICMP]" + "\033[0m"

    print(f'\n\t\t     {ICMP_HEADER}\n')

    if TYPE == 3:
        print(f'     -> Type: Destination Unreachable (3)')
    elif TYPE == 5:
        print(f'     -> Type: Redirect (5)')
    elif TYPE == 8:
        print(f'     -> Type: Echo (8)')
    elif TYPE == 0:
        print(f'     -> Type: Echo Reply (0)')
    elif TYPE == 11:
        print(f'     -> Type: Time Exceeded (11)')

    if CODE == 0:
        print(f'     -> Code: Network Unreachable (0)')
    elif CODE == 1:
        print(f'     -> Code: Host Unreachable (1)')
    elif CODE == 2:
        print(f'     -> Code: Protocol Unreachable (2)')
    elif CODE == 3:
        print(f'     -> Code: Port Unreachable (3)')

    print(f'     -> FCS: 0x {CHECK_SUM[0]} {CHECK_SUM[1]}')
    print(f'     -> Identifier: {IDENTIFIER}')
    print(f'     -> Sequence: {SEQUENCE_NUM}')

    if TYPE in [5, 3, 11]:
        ipv4_frame(packet[8:], False)
    elif TYPE in [5]:

        for number in GET_GATEWAY:
            GATEWAY = f'{GATEWAY}{number}.'

        GATEWAY = GATEWAY[:-1]

        print(f'     -> Gateway Internet Address: {GATEWAY}')
        input('\n\t')
    else:
        input('\n\t')

def ipv6_frame(packet : list):

    IPV6_HEADER = "\033[1m" + "[IPV6]" + "\033[0m"
    FIRST_LAYER = packet[:4]
    LAYER = ''
    PAYLOAD = ''
    SRC_ADDR = ''
    DEST_ADDR = ''

    for byte in FIRST_LAYER:
        LAYER = f'{LAYER}{byte_binary(byte)}'

    VERSION = LAYER[:4]
    TRAFFIC_CLASS = LAYER[4:12]
    FLOW_LABEL = LAYER[12:]

    PAYLOAD_LEN = packet[4:6]

    for byte in PAYLOAD_LEN:
        PAYLOAD = f'{PAYLOAD}{byte_binary(byte)}'

    NEXT_HEADER = packet[6]
    HOP_LIMIT = packet[7]

    GET_SRC_ADDR = decimal_to_hexa(packet[8:24])

    for byte in range(0, len(GET_SRC_ADDR), 2):
        SRC_ADDR = f'{SRC_ADDR}{GET_SRC_ADDR[byte]}{GET_SRC_ADDR[byte + 1]}:'

    SRC_ADDR = SRC_ADDR[:-1]

    GET_DEST_ADDR = decimal_to_hexa(packet[24:40])

    for byte in range(0, len(GET_DEST_ADDR), 2):
        DEST_ADDR = f'{DEST_ADDR}{GET_DEST_ADDR[byte]}{GET_DEST_ADDR[byte + 1]}:'

    DEST_ADDR = DEST_ADDR[:-1]

    print(f'\n\t\t     {IPV6_HEADER}\n')

    print(f'  -> Version: {binary_to_decimal(int(VERSION))} (Ipv6)')
    print(f'  -> Traffic Class: {binary_to_decimal(int(TRAFFIC_CLASS))}')

    if TRAFFIC_CLASS[0] == '1':
        print('     - No specific traffic.')
    if TRAFFIC_CLASS[1] == '1':
        print('     - Background data.')
    if TRAFFIC_CLASS[2] == '1':
        print('     - Unattended data traffic.')
    if TRAFFIC_CLASS[3] == '1':
        print('     - Reserved.')
    if TRAFFIC_CLASS[4] == '1':
        print('     - Attended bulk data traffic.')
    if TRAFFIC_CLASS[5] == '1':
        print('     - Reserved.')
    if TRAFFIC_CLASS[6] == '1':
        print('     - Interactive traffic.')
    if TRAFFIC_CLASS[7] == '1':
        print('     - Control traffic.')

    print(f'  -> Flow Label: {binary_to_decimal(int(FLOW_LABEL))}')
    print(f'  -> Payload Length: {binary_to_decimal(int(PAYLOAD))} bytes')

    if NEXT_HEADER == 58:
        print(f'\n  -> Next header: {NEXT_HEADER} (ICMPv6)')
        print(f"        - Internet Control Message Protocol Version 6")
    elif NEXT_HEADER == 0:
        print(f'\n  -> Next header: {NEXT_HEADER} (Hop-by-hop)')
        print(f"        - Hop by hop Options Header")
    elif NEXT_HEADER == 17:
        print(f'\n  -> Next header: {NEXT_HEADER} (UDP)')
        print(f"        - User Datagram Protocol")
    elif NEXT_HEADER == 6:
        print(f'\n  -> Next header: {NEXT_HEADER} (TCP)')
        print(f"        - Transmission Control Protocol")
    elif NEXT_HEADER == 41:
        print(f'\n  -> Next header: {NEXT_HEADER} (Encapsulated)')
        print(f"        - Encapsulated iPv6 Header")
    elif NEXT_HEADER == 43:
        print(f'\n  -> Next header: {NEXT_HEADER} (Routing Header)')
    elif NEXT_HEADER == 44:
        print(f'\n  -> Next header: {NEXT_HEADER} (Fragment Header)')
    elif NEXT_HEADER == 50:
        print(f'\n  -> Next header: {NEXT_HEADER} (Encapsulating)')
        print(f"        - Encapsulating Security Payload Header")
    elif NEXT_HEADER == 51:
        print(f'\n  -> Next header: {NEXT_HEADER} (Authentication Header)')
    elif NEXT_HEADER == 59:
        print(f'\n  -> Next header: {NEXT_HEADER} (No Next Header)')
    elif NEXT_HEADER == 60:
        print(f'\n  -> Next header: {NEXT_HEADER} (Destination Options Header)')

    print(f'  -> Hop Limit: {HOP_LIMIT} hops')

    SRC_IP = reformat_ipv6(SRC_ADDR).lower()
    DEST_IP = reformat_ipv6(DEST_ADDR).lower()

    print(f'\n  -> Source Address: {SRC_IP}')
    
    print(f'\n  -> Destination Address: {DEST_IP}')
    
    input('\n\t')

def ethernet_frame(packet : list, name : str):

    name = name.split(".")
    name = name[0].title()

    os.system(CLEAR)

    print(f'\n\t----- Output for {name} -----')

    GET_DEST_MAC = decimal_to_hexa(packet[:6])
    GET_SRC_MAC = decimal_to_hexa(packet[6:12])
    GET_TYPE = decimal_to_hexa(packet[12:14])
    GET_FCS = decimal_to_hexa(packet[-4:])

    DEST_MAC = ''
    SRC_MAC = ''
    TYPE = f'0x{GET_TYPE[0]}{GET_TYPE[1]}'
    FCS = f'0x {GET_FCS[0]} {GET_FCS[1]} {GET_FCS[2]} {GET_FCS[3]}'

    for byte in GET_DEST_MAC:
        DEST_MAC = f'{DEST_MAC}{byte}:'

    DEST_MAC = DEST_MAC[:-1]

    for byte in GET_SRC_MAC:
        SRC_MAC = f'{SRC_MAC}{byte}:'

    SRC_MAC = SRC_MAC[:-1]

    ETHER_HEADER = "\033[1m" + "[ETHERNET]" + "\033[0m"

    print(f'\n\t\t   {ETHER_HEADER}\n')

    print(f'  -> Destination MAC Address: {DEST_MAC}')

    DEST_MAC_MULTI, DEST_MAC_LOCAL = get_oui_nic(DEST_MAC)

    if DEST_MAC == 'FF:FF:FF:FF:FF:FF':
        print('     - Es una MAC Address BROADCAST.')
    else:
        if DEST_MAC_MULTI:
            print('     - Es una MAC Address MULTICAST.')
        else:
            print('     - Es una MAC Address UNICAST.')

    if DEST_MAC_LOCAL:
        print('     - Locally Administred.')
    else:
        print('     - Globally Unique.')

    print(f'\n  -> Source MAC Address: {SRC_MAC}')

    SRC_MAC_MULTI, SRC_MAC_LOCAL = get_oui_nic(SRC_MAC)

    if SRC_MAC == 'FF:FF:FF:FF:FF:FF':
        print('     - Es una MAC Address BROADCAST.')
    else:
        if SRC_MAC_MULTI:
            print('     - Es una MAC Address MULTICAST.')
        else:
            print('     - Es una MAC Address UNICAST.')

    if SRC_MAC_LOCAL:
        print('     - Locally Administred.')
    else:
        print('     - Globally Unique.')

    if TYPE == '0x0806':
        TYPE = f'{TYPE} (ARP)'
    elif TYPE == '0x0800':
        TYPE = f'{TYPE} (Ipv4)'
    elif TYPE == '0x86DD':
        TYPE = f'{TYPE} (Ipv6)'

    print(f'\n  -> Ethertype: {TYPE}')

    print(f'     - {BYTES} bytes de carga útil de Ethernet')
    print(f'     - FCS: {FCS}')

    if TYPE == '0x0806 (ARP)':
        arp_frame(packet[14:-4])
    elif TYPE == '0x0800 (Ipv4)':
        ipv4_frame(packet[14:-4], True)
    elif TYPE == '0x86DD (Ipv6)':
        ipv6_frame(packet[14:-4])
    else:
        input('\t\n')