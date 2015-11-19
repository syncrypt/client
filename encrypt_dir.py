"Encrypt all the files in a folder and print out hash and filesize."
import hashlib
import os
import os.path
import sys
from pprint import pprint

import Crypto.Util.number
import rsa
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

aes_key_len = 256
rsa_key_len = 1024
hash_algo = 'sha256'
iv = 'This is an IV456'

# TODO: dont generate a new key erry time
(pubkey, privkey) = rsa.newkeys(rsa_key_len, poolsize=8)
block_size = 16
folder = sys.argv[1]

pad = lambda s: s + str.encode((block_size - len(s) % block_size) * chr(block_size - len(s) % block_size))

fileinfo = []

for (dir, dunno, files) in os.walk(folder):
    for f in files:
        if f.endswith('.encrypted') or f.endswith('.key'):
            continue
        abspath = os.path.join(dir, f)
        print (abspath)

        with open(abspath, 'rb') as unencrypted:
            # TODO: dont read whole file into memory but stream it
            original_content = unencrypted.read()
            original_size = len(original_content)

            h = hashlib.new(hash_algo)
            h.update(original_content)
            original_hash = h.hexdigest()

            aes_key = os.urandom(aes_key_len >> 3)
            aes_engine = AES.new(aes_key, AES.MODE_CBC, iv)

            with open(abspath + '.key', 'wb') as encrypted_key_file:
                encrypted_key = rsa.encrypt(aes_key, pubkey)
                encrypted_key_file.write(encrypted_key)

            with open(abspath + '.encrypted', 'wb') as encrypted_file:
                enc = aes_engine.encrypt(pad(original_content))
                encrypted_size = len(enc)
                encrypted_file.write(enc)

        print ("\t- File hash:\t{0}".format(original_hash))
        print ("\t- File size:\t{0}".format(original_size))
        print ("\t- File* size:\t{0}".format(encrypted_size))
        print ("\t- Key size:\t{0} ({1} bit)".format(aes_key_len >> 3, aes_key_len))
        print ("\t- Key* size:\t{0}".format(len(encrypted_key)))
        print ()
        fileinfo.append({
            'path': abspath,
            'file_hash': original_hash,
            'file_size': original_size,
            'file_size*': encrypted_size,
            'key_size': aes_key_len >> 3,
            'key_size*': len(encrypted_key)
        })
pprint(fileinfo)
