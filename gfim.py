import argparse
import datetime;
import json
import sys
import time
from utils import *
    


def add_metadata(data, hash_func):
    data.update({'metadata': {'timestamp': str(datetime.datetime.now())}})
    data['metadata'].update({'hash_function': hash_func})


def store(files, hash_func):
    try:
        password = getpass.getpass("Enter password: ")
        password_bytes = password.encode("utf-8")
        with open(private_file, "rb") as priv:
            private_key = serialization.load_pem_private_key(
                priv.read(),
                password=password_bytes  # Or password=b"yourpassword" if encrypted
            )
    except Exception as e:
        status_alert(e)
        raise 

    flag = True
    counter = 0
    data = {}
    start_time = time.perf_counter()
    add_metadata(data, hash_func) 
    for file in files:
        counter += 1
        filename = str(file)
        try:
            digest = hash_file(file, hash_func)
            data.update({filename: digest})
        except:
            status_alert("a file was modified or deleted:")
            alert_note(f"Path: {filename}")
            flag = False
            counter -= 1

    with open(Path(archive_file), "w") as a:
        dump = json.dumps(data)
        a.write(dump)
    try:
        sign(password_bytes)
    except Exception as e:
        status_error(e)
        raise

    end_time = time.perf_counter()
    elapsed = end_time - start_time

    if flag:
        status_ok("Data was stored and signed correctly.")
    print("<--------------------------------------------->")
    print("Archive information:")
    info_dash(f"Stored: {counter}/{len(files)} file(s)")
    info_dash(f"Altered: {len(files)-counter}")
    info_dash(f"Time to store and sign: {elapsed:.5f}s")
    info_dash(f"Timestamp: {data['metadata']['timestamp']}")
    info_dash(f"Hash function: {data['metadata']['hash_function']}")



def verify(files, hash_func):
    try:
        with open(Path(archive_file),'r') as a:
            #once we have all the files open we compare the digests
            counter = 0
            data = json.load(a)
            flag = True
    except Exception as e:
        status_error(e)
        raise 

    #check the validity of the .json first
    try:
        prove()
    except Exception as e:
        status_alert(e)
        raise 

    for file in files:
        counter += 1
        filename = str(file)
        try:
            curr_file = Path(file)
            curr_digest = hash_file(curr_file, hash_func) 
            digest = data[filename]
            if(curr_digest != digest):
                status_alert("a file was modified or deleted:")
                counter -= 1
                alert_note(f"Path: {filename}")
                flag = False
        except:
            status_alert("a file was modified or deleted:")
            flag = False
            alert_note(f"Path: {filename}")
            counter -= 1

    if flag:
        status_ok("No changes have been detected.")
    print("<--------------------------------------------->")
    print("Archive information:")
    info_dash(f"Timestamp: {data['metadata']['timestamp']}")
    info_dash(f"Hash function: {data['metadata']['hash_function']}")
    info_dash(f"Verified: {counter}/{len(files)} file(s)")
    info_dash(f"Altered: {len(files)-counter}")


#initialization of argparse
parser = argparse.ArgumentParser (
        prog="main.py",
        epilog="<-- Mendacem memorem esse oportet -->",
)


parser.add_argument('--store', help='hashes content of .yaml and digitally signs it.',action='store_true')
parser.add_argument('--verify', help='verifies contents of the archive.', action='store_true')
parser.add_argument('--gen', help='generates keys for signing.', action='store_true')
args = parser.parse_args()


init(autoreset=True)
def main():
    config = load_yaml()
    files = config['to-monitor']['files']
    hash_func = config['hash']
    try:
        if args.store:
            store(files, hash_func)
        elif args.verify:
            verify(files, hash_func)
        elif args.gen:
            gen()
        return 0
    except:
        return 1
        

if __name__ == "__main__":
    sys.exit(main())

