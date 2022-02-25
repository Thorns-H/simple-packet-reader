import os
import platform
from unicodedata import decimal

if platform.system() != 'Linux':
    CLEAR = 'cls'
else:
    CLEAR = 'clear'

BROADCAST = 'FF:FF:FF:FF:FF:FF'
global BYTES
BYTES = 0

def read_file(packet):

    global BYTES

    bytes = []

    with open(packet, 'rb') as file:
        while True:
            binary = file.read(1)
            if not binary:
                break
            bytes.append(int.from_bytes(binary, byteorder = 'big'))

        BYTES = len(bytes) - 18

        return bytes

def decimal_to_hexa(numbers : list):

    hexa_format = []

    for number in numbers:
        convertion = hex(number).upper()

        convertion = convertion[2:]

        if len(convertion) < 2:
            convertion = f'0{convertion}'

        hexa_format.append(convertion)

    return hexa_format

def get_oui_nic(MAC):
    MAC = MAC.split(':')

    MULTICAST = False
    LOCAL = False

    for i in range(len(MAC)):
        MAC[i] = MAC[i].lower()

    int_value = int(MAC[0], base = 16)

    bin_value = bin(int_value)[2:].zfill(8)

    if bin_value[7] == '1':
        MULTICAST = True
    if bin_value[6] == '1':
        LOCAL = True

    return MULTICAST, LOCAL

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

def binary_to_decimal(binary):

    binary1 = binary
    decimal, i, n = 0, 0, 0
    while(binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary // 10
        i += 1

    return decimal

def byte_binary(int_value):

    bin_value = bin(int_value)[2:].zfill(8)

    return bin_value

def ipv4_frame(packet):

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
        print(f'        - Differentiated Services Code Point: {binary_to_decimal(int(DSCP))} (Standard)')

    if ECN == '00':
        print(f'        - Explicit Congestion Notification: {binary_to_decimal(int(ECN))} (Non-ETC)')

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

    print(f'\n     -> Time to Live (TTL): {TTL} seconds')

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

    input('\n\t')

def ethernet_frame(packet, name):

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

    if DEST_MAC == BROADCAST:
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

    if SRC_MAC == BROADCAST:
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
        ipv4_frame(packet[14:-4])
    else:
        input('\t\n')