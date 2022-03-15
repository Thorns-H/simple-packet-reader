from src.protocols import ethernet_frame
from src.helpers import read_file, CLEAR
from src.helpers import WARNING, ITALIC, GREEN, RED, END, UNDERLINE
import os

global TESTING
TESTING = "test_files"
PATH = os.getcwd()

def main():
    global TESTING
    while True:
        try:
            os.system(CLEAR)
            os.system(f'cd && cd {PATH}/{TESTING} && ls | sort > ../src/files.txt')

            with open('src/files.txt') as f:
                data = f.readlines()

            print(f'\n\t\t--- {ITALIC}Testing Directory{END} ---\n')

            for i in range(len(data)):
                print(f'\t{ITALIC}[{i}] - {data[i][:-1]}{END}')

            print(f'\n\t\t{WARNING}@Press CTRL + C to leave!{END}')

            file = input('\n\tSelect: ')

            try:
                file = int(file)
            except ValueError:
                file = str(file)

            if type(file) == str:
                if file.lower() in ["tested", "old"]:
                    if TESTING == "tested":
                        print(f"\n\t{WARNING}@WARNING:{END} Already working with old files!")
                    else:
                        TESTING = "tested"
                        print(f'\n\t{GREEN}@SUCCESS:{END} Switched to old files!')
                elif file.lower() in ["new", "working"]:
                    if TESTING == "test_files":
                        print(f"\n\t{WARNING}@WARNING:{END} Already working with new files!")
                    else:
                        TESTING = "test_files"
                        print(f'\n\t{GREEN}@SUCCESS:{END} Switched to old files!')
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
            break
        
    os.system(CLEAR)

if __name__ == '__main__':
    main()