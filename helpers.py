import os

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

        
def ethernet_frame(packet, name):

    name = name.split(".")
    name = name[0].title()

    os.system('clear')

    print(f'\n\t----- Output for {name} -----\n')

    GET_DEST_MAC= decimal_to_hexa(packet[:6])
    GET_SRC_MAC = decimal_to_hexa(packet[6:12])
    GET_TYPE = decimal_to_hexa(packet[12:14])

    DEST_MAC = ''
    SRC_MAC = ''
    TYPE = f'0x{GET_TYPE[0]}{GET_TYPE[1]}'

    for byte in GET_DEST_MAC:
        DEST_MAC = f'{DEST_MAC}{byte}:'

    DEST_MAC = DEST_MAC[:-1]

    for byte in GET_SRC_MAC:
        SRC_MAC = f'{SRC_MAC}{byte}:'

    SRC_MAC = SRC_MAC[:-1]

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

    input('\t\n')