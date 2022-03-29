from time import sleep
from src.protocols import ethernet_frame, pcap_package
from src.helpers import read_file, CLEAR, REDIRECT
from src.helpers import WARNING, ITALIC, GREEN, RED, END, UNDERLINE
import os

global TESTING
TESTING = "test_files"
PATH = os.getcwd()

# sudo -E python3 run.py

def main():
    global TESTING
    filter = False
    to_find = ''
    while True:
        try:
            os.system(CLEAR)
            os.system(f'cd && cd {PATH}/{TESTING} && {REDIRECT} | sort > ../src/files.txt')

            with open('src/files.txt') as f:
                data = f.readlines()

            print(f'\n\t\t--- {ITALIC}Testing Directory{END} ---\n')

            for i in range(len(data)):
                if not filter:
                    print(f'\t{ITALIC}[{i}] - {data[i][:-1]}{END}')
                else:
                    if to_find in data[i][:-1]:
                        print(f'\t{ITALIC}[{i}] - {data[i][:-1]}{END}')

            if filter:
                print(f'\n\t{WARNING}@WARNING:{END} Currently working by filter: "{to_find}"!')

            print(f'\n\t\t{WARNING}Press CTRL + C to leave!{END}')

            file = input(f'\n\tSelect: {ITALIC}')
            print(f'{END}', end = "")

            try:
                file = int(file)
            except ValueError:
                file = str(file)

            if type(file) == str:
                if file.lower().startswith("filter:") and len(file) > 7:
                    to_find = file[7:].lower()
                    if to_find != "all":
                        print(f'\n\t{GREEN}@SUCCESS:{END} Enabled filter by "{to_find}"!')
                        filter = True
                    else:
                        print(f'\n\t{GREEN}@SUCCESS:{END} Restarting files!')
                        filter = False
                elif file.lower() in ["tested", "old"]:
                    if TESTING == "tested":
                        print(f"\n\t{WARNING}@WARNING:{END} Already working with old files!")
                    else:
                        TESTING = "tested"
                        print(f'\n\t{GREEN}@SUCCESS:{END} Switched to old files!')
                elif file.lower() in ["new"]:
                    if TESTING == "test_files":
                        print(f"\n\t{WARNING}@WARNING:{END} Already working with new files!")
                    else:
                        TESTING = "test_files"
                        print(f'\n\t{GREEN}@SUCCESS:{END} Switched to old files!')
                elif file.lower() == "working":
                    print(f'\n\t{WARNING}@ADVERTISEMENT:{END} Currently working with {TESTING}!')
                elif file.lower() == "mode:pcap":
                    pcap_package()
                elif file != '':
                    print(f'\n\t{RED}@ERROR:{END} {UNDERLINE}{file}{END} is not a valid index!')
                else:
                    print(f'\n\t{RED}@ERROR:{END} You need to type something!')
                    
                input('\t\n')
            else:
                if file >= len(data) or file < 0:
                    print(f'\n\t{RED}@ERROR:{END} File with index "{file}" does not exists!')
                    input('\t\n')
                else:
                    ethernet_frame(read_file(f'{TESTING}/{data[file][:-1]}'), f'{data[file][:-1]}')  
        except KeyboardInterrupt:
            print(f'\n\n\t{GREEN}@SUCCESS:{END} Closing the program!')
            sleep(1)
            break
        
    os.system(CLEAR)

if __name__ == '__main__':
    main()