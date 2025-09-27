# SigFIM
SigFIM is a small File Integrity Montor (FIM) CLI tool that verifies the integrity of files against corruption or tampering.

This tool applies a chosen hash function to files inside the list (in the .YAML file) that we want to monitor, and saves a "digested" version of each file, storing them in the JSON archive. This permits us verify and recalculate the hashes from the file system and compare them with the ones in the archive. If a file has been tampered or modified it will be reported.
The tool also uses [EdDSA25519](https://en.wikipedia.org/wiki/EdDSA) which uses [Elliptic Curve Cryptography](https://en.wikipedia.org/wiki/Elliptic_curve) for digitally signing the archive, EdDSA was chosen since it is one of the fastest digital
signatures algorithms without sacrificing security and simplicity, in particular Curve25519 was chosen since it's notably fast and designed to be robust against common attacks, providing a solid choice for integrity verification.
 
So, this project uses:
- SHA256, MD5, BLAKE3 and more for hashing
- EdDSA25519 for digital signatures
- PEM for storing the private and public keys
- JSON for storing an archive of hashes
- YAML for manual configuration

## Installation
Clone this repository:
```Bash
git clone https://github.com/demr64/SigFIM.git
cd SigFIM
```

## Manual
We may start by setting up things in our .yaml file.
Under the ```to-monitor``` and ```files``` section, and we may list the absolute paths of the files that we want to monitor, every of them on a new line preceded by a dash, now we can go in the ```hash``` section and we may write the hashing algorithm that we want to use, note that in this section we are allowed to list down every algorithm supported by the [hashlib](https://docs.python.org/3/library/hashlib.html) library.

By now we are ready to run our gfim script:
```
python gfim.py --gen
```
which will query us with a password that will be requested in the next storing sessions. this command generates a private and public key stored in two generated .pem files.
After inserting the absolute file paths in the ```config.yaml``` file under the ```to-monitor``` section, we may now want to store their hashes. We do so with
```
python gfim.py --store
````
this command will store the hashes in the archive.json and will also digitally sign it, and produce a signature to compare to.
Lastly, we may run the following to check the validity of our data
```
python gfim.py --verify
```

## License

MIT License

See [LICENSE](LICENSE.txt) for more details.
