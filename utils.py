import hashlib
import yaml
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import getpass
from colorama import init, Fore, Style


config_file = 'config.yaml'
archive_file = 'archive.json'
private_file = 'private_key.pem'
public_file = 'public_key.pem'
signature_file = 'signature.sig'


def info_dash(msg):
   print(f"[{Fore.CYAN}-{Style.RESET_ALL}] {msg}")


def alert_note(msg):
   print(f"[{Fore.YELLOW}!{Style.RESET_ALL}] {msg}")


def status_ok(msg):
   print(f"[{Fore.GREEN}OK{Style.RESET_ALL}]: {msg}")


def status_alert(msg):
   print(f"[{Fore.LIGHTRED_EX}ALERT{Style.RESET_ALL}]: {msg}")


def status_error(error):
    print(f"[{Fore.RED}ERROR{Style.RESET_ALL}]: {error}")


def hash_file(path, hash_func):
    try:
        hash_func = getattr(hashlib, hash_func)
        with open(Path(path), 'rb') as f:
            return hash_func(f.read()).hexdigest()
    except Exception as e:
        raise 


def load_yaml() -> dict:
    with open(config_file, 'r') as c:
        config = yaml.safe_load(c)
    return config


def gen():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    password = getpass.getpass("Enter a password: ")
    password_bytes = password.encode("utf-8")

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password_bytes)
    )

    with open(Path(public_file), 'wb') as public:
        public.write(pub_bytes)
    with open(Path(private_file), 'wb') as private:
        private.write(priv_bytes)
    status_ok("Successfully generated a new pair of keys.")


def sign(password_bytes):
    try:
        with open(Path(archive_file), 'rb') as a:
            with open(private_file, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password_bytes
                )
            signature = private_key.sign(a.read())
        with open(Path(signature_file), 'wb') as sig:
            sig.write(signature)
    except Exception as e:
        raise


def prove():
    try:
        with open(Path(signature_file), 'rb') as sig:
            signature = sig.read()
            with open(Path(archive_file), 'rb') as a:
                with open(Path(public_file), 'rb') as public:
                        public_key = serialization.load_pem_public_key(public.read())
                        public_key.verify(signature, a.read())

    except InvalidSignature:
        raise ValueError("Signature verification failed.")
    except Exception as e:
        raise 
