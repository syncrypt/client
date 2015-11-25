import hashlib
import os
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

pad = lambda s: s + str.encode((block_size - len(s) % block_size) * chr(block_size - len(s) % block_size))

class Bundle(object):
    'A Bundle represents a file with additional information'

    __slots__ = ('path', 'vault', 'file_hash', 'file_size', 'file_size_crypt',
            'key_size', 'key_size_crypt')

    def __init__(self, abspath, vault):
        self.vault = vault
        self.path = abspath

        # encrypt file now. eventually this will be done only if
        # necessary and not at this place.
        with open(abspath, 'rb') as unencrypted:
            # TODO: dont read whole file into memory but stream it
            original_content = unencrypted.read()
            original_size = len(original_content)

            h = hashlib.new(hash_algo)
            h.update(original_content)
            original_hash = h.hexdigest()

            aes_key = os.urandom(aes_key_len >> 3)
            aes_engine = AES.new(aes_key, AES.MODE_CBC, iv)

            with open(self.path_key, 'wb') as encrypted_key_file:
                encrypted_key = rsa.encrypt(aes_key, pubkey)
                encrypted_key_file.write(encrypted_key)

            with open(self.path_crypt, 'wb') as encrypted_file:
                enc = aes_engine.encrypt(pad(original_content))
                encrypted_size = len(enc)
                encrypted_file.write(enc)

        self.file_hash = original_hash
        self.file_size = original_size
        self.file_size_crypt = encrypted_size
        self.key_size = aes_key_len >> 3
        self.key_size_crypt = len(encrypted_key)

    def __str__(self):
        return "<Bundle: {0.relpath} ({0.file_size_crypt} bytes encrypted)>".format(self)

    @property
    def relpath(self):
        return os.path.relpath(self.path, self.vault.folder)

    @property
    def path_crypt(self):
        return self.path + '.encrypted'

    @property
    def path_key(self):
        return self.path + '.key'
