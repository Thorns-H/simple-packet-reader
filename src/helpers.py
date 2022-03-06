import platform

if platform.system() != 'Linux':
    CLEAR = 'cls'
else:
    CLEAR = 'clear'

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