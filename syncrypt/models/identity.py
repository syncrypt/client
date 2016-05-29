import hashlib
import logging
import os
import os.path

from Crypto.PublicKey import RSA
import Crypto.Util.number

logger = logging.getLogger(__name__)


class Identity(object):
    '''represents an RSA key pair'''
    def __init__(self, id_rsa_path, id_rsa_pub_path, config):
        self.id_rsa_path = id_rsa_path
        self.id_rsa_pub_path = id_rsa_pub_path
        self.config = config

    @classmethod
    def from_public_key(cls, key, config):
        identity = cls(None, None, config)
        identity._keypair = (RSA.importKey(key), None)
        return identity

    @property
    def private_key(self):
        try:
            return self._keypair[1]
        except AttributeError:
            self.read()
            return self._keypair[1]

    @property
    def public_key(self):
        try:
            return self._keypair[0]
        except AttributeError:
            self.read()
            return self._keypair[0]

    def read(self):
        with open(self.id_rsa_pub_path, 'rb') as id_rsa_pub:
            public_key = RSA.importKey(id_rsa_pub.read())
        with open(self.id_rsa_path, 'rb') as id_rsa:
            private_key = RSA.importKey(id_rsa.read())
        self._keypair = (public_key, private_key)

    def key_size(self):
        return Crypto.Util.number.size(self.private_key.n)

    def init(self):
        if not os.path.exists(self.id_rsa_path) or not os.path.exists(self.id_rsa_pub_path):
            self.generate_keys()
        else:
            self.read()

            # Do NOT enforce a specific key length yet
            # if Crypto.Util.number.size(self.public_key.n) != self.config.rsa_key_len or \
            #        Crypto.Util.number.size(self.private_key.n) != self.config.rsa_key_len - 1:
            #    self.public_key = None
            #    self.private_key = None
            #    raise SecurityError(
            #            'Vault key is not of required length of %d bit.' \
            #                    % self.config.rsa_key_len)

    def export_public_key(self):
        'return the public key serialized as bytes'
        return self.public_key.exportKey('DER')

    def generate_keys(self):
        if not os.path.exists(os.path.dirname(self.id_rsa_path)):
            os.makedirs(os.path.dirname(self.id_rsa_path))
        logger.info('Generating a %d bit RSA key pair...', self.config.rsa_key_len)
        keys = RSA.generate(self.config.rsa_key_len)
        with open(self.id_rsa_pub_path, 'wb') as id_rsa_pub:
            id_rsa_pub.write(keys.publickey().exportKey())
        with open(self.id_rsa_path, 'wb') as id_rsa:
            id_rsa.write(keys.exportKey())
        self._keypair = (keys.publickey(), keys)
        assert self._keypair[0] is not None

    def get_fingerprint(self):
        assert self.public_key
        pk_hash = hashlib.new(self.config.hash_algo)
        pk_hash.update(self.public_key.exportKey('DER'))
        return pk_hash.hexdigest()[:self.config.fingerprint_length]
