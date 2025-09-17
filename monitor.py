import yaml
import argparse
import datetime;
import json
from utils import *
    

def add_metadata(data):
    data.update({'metadata': {'timestamp': str(datetime.datetime.now())}})

def store(files):
    try:
        password = getpass.getpass("Enter password: ")
        password_bytes = password.encode("utf-8")
        with open(private_file, "rb") as priv:
            private_key = serialization.load_pem_private_key(
                priv.read(),
                password=password_bytes  # Or password=b"yourpassword" if encrypted
            )
    except Exception as e:
        print("[!] ALERT: invalid password or serialization fail:", e)
        exit(1)

    data = {}
    add_metadata(data) 
    for file in files:
        filename = str(file)
        try:
            digest = hash_file(file)
            data.update({filename: digest})
        except:
            print("[!] ALERT: a file at location:")
            print(filename)
            print("was modified or deleted.")

    with open(archive_file, "w") as a:
        dump = json.dumps(data)
        a.write(dump)
    sign(password_bytes)
    print("OK: Data was stored and signed.")


def verify(files):
    with open(archive_file,'r') as a:
        #once we have all the files open we compare the digests
        data = json.load(a)
        flag = True

        #check the validity of the .json first
        prove()

        for file in files:
            filename = str(file)
            try:
                curr_file = Path(file)
                curr_digest = hash_file(curr_file) 
                digest = data[filename]
                if(curr_digest != digest):
                    print("[!] ALERT: a file has been modified.")
                    print("- Path:", filename)
                    print("- Current digest:", curr_digest)
                    print("- Archived digest:", digest)
                    flag = False
            except:
                print("[!] ALERT: a file at location:")
                print(filename)
                print("was modified or deleted.")

        if flag:
            print("OK: No changes have detected.")


#reads the .yaml content of 'to-monitor'
def read_yaml_files() -> list:
    to_analyze = []
    with open(config_file, 'r') as c:
        config = yaml.safe_load(c)
        #handle files
        to_monitor = config['to-monitor']['files']
        if to_monitor == None:
            return []

        for i in range(0, len(to_monitor)):
            path = Path(to_monitor[i])
            to_analyze.append(path)

    return to_analyze


#initialization of argparse
parser = argparse.ArgumentParser (
        prog="main.py",
        epilog="--Mendacem oportet esse memorem--",
)

parser.add_argument('--store', help='hashes content of .yaml',action='store_true')
parser.add_argument('--verify', help='checks contents', action='store_true')
parser.add_argument('--gen', help='generates keys', action='store_true')
args = parser.parse_args()

def main():
    files = read_yaml_files()
    if args.store:
        store(files)
    elif args.verify:
        verify(files)
    elif args.gen:
        gen()
        

if __name__ == "__main__":
    main()
