import platform
import ipaddress

if platform.system() != 'Linux':
    CLEAR = 'cls'
    REDIRECT = 'dir /b'
else:
    CLEAR = 'clear'
    REDIRECT = 'ls'

WARNING = '\033[93m'
ITALIC = '\x1B[3m'
GREEN = '\033[92m'
RED = '\033[91m'
END = '\033[0m'
UNDERLINE = '\033[4m'

def read_file(file_bin : str):

    global BYTES

    bytes = []

    with open(file_bin, 'rb') as file:
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

def get_oui_nic(MAC : str):
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

def binary_to_decimal(binary : str):

    binary1 = binary

    decimal, i, n = 0, 0, 0

    while(binary != 0):

        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary // 10
        
        i += 1

    return decimal

def byte_binary(int_value : int):

    bin_value = bin(int_value)[2:].zfill(8)

    return bin_value

def reformat_ipv6(ipv6 : str):
    ipv6 = ipv6.split(':')

    new_format_address = []

    for frame in ipv6:
        if frame.startswith('0'):
            if frame == '0000':
                frame = int(frame)
                frame = str(frame)
                
                new_format_address.append(frame)
            else:
                for i in range(len(frame)):
                    if frame[i] != '0':
                        new_format_address.append(frame[i:])
                        break
        else:
            new_format_address.append(frame)
            
    address = ''
    indices = []

    for value in range(len(new_format_address)):
        if new_format_address[value] == '0':
            indices.append(value)

    if new_format_address == ['0','0','0','0','0','0','0','0']:
        return '::'

    found_more_zeros = False

    for i in range(len(indices) - 1):
        if indices[i] + 1 != indices[i + 1]:
            found_more_zeros = True
            break
        else:
            found_more_zeros = False

    if found_more_zeros:

        for data in new_format_address:
            address = f'{address}{data}:'

        address = address[:-1]

        address = str(ipaddress.ip_address(address))
    else:
        new_format_address = list(dict.fromkeys(new_format_address))

        for data in new_format_address:
            address = f'{address}{data}:'

        address = address[:-1]

        if f'{address[0]}{address[1]}' == '0:':
            address = address[2:]
            address = f'::{address}'
        elif f'{address[-2]}{address[-1]}' == ':0':
            address = address[:-2]
            address = f'{address}::'
        elif address.find(':0:'):
            address = address.replace(':0:', '::')

    return address  

def get_domain(packet : list):

    name = packet
    decimal_name = []
    domain = ''

    for letter in name:
        if letter != 0:
            decimal_name.append(letter)
        else:
            break
    
    index = 0
    point_values = []
    
    while index != len(decimal_name):

        value = decimal_name[index]
        index = index + value + 1
        point_values.append(index)
    
    for i in range(0, len(decimal_name)):
        if i not in point_values:
            domain = f'{domain}{chr(decimal_name[i])}'
        else:
            domain = f'{domain}.'

    return domain