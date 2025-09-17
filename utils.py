import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import getpass

config_file = 'config.yaml'
archive_file = 'archive.json'
private_file = 'private_key.pem'
public_file = 'public_key.pem'
signature_file = 'signature.sig'

def hash_file(path):
    with open(Path(path), 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def gen():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    password = getpass.getpass("Enter password: ")
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

def sign(password_bytes):
    with open(Path(archive_file), 'rb') as a:
        with open(private_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password_bytes
            )
        signature = private_key.sign(a.read())
    with open(Path(signature_file), 'wb') as sig:
        sig.write(signature)

def prove() -> int:
    with open(Path(signature_file), 'rb') as sig:
        signature = sig.read()
        with open(Path(archive_file), 'rb') as a:
            with open(Path(public_file), 'rb') as public:
                try:
                    public_key = serialization.load_pem_public_key(public.read())
                    public_key.verify(signature, a.read())
                    return 0 
                except Exception as e:
                    print("[!] ALERT: the .json has been tampered or there was")
                    print("a serialization error.",e)
                    return 1 
    


