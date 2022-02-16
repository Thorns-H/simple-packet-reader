from helpers import read_file, ethernet_frame, CLEAR
import os

TESTING = "test_files"
PATH = os.getcwd()

def main():
    while True:
        try:
            os.system(CLEAR)
            os.system(f'cd && cd {PATH}/{TESTING} && ls -t > ../files.txt')

            with open('files.txt') as f:
                data = f.readlines()

            print('\n\t\t--- Files to Read ---\n')

            for i in range(len(data)):
                print(f'\t[{i}] - {data[i][:-1]}')

            print('\n\t@Press CTRL + C to leave!')

            file = int(input('\n\tSelect: '))

            if file >= len(data) or file < 0:
                print(f'\n\t@ERROR: File with index "{file}" does not exists!')
                input('\t\n')
            else:
                ethernet_frame(read_file(f'{TESTING}/{data[file][:-1]}'), f'{data[file][:-1]}')  
        except KeyboardInterrupt:
            break
        
    os.system(CLEAR)

if __name__ == '__main__':
    main()