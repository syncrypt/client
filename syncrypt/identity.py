import os
import os.path

from Crypto.PublicKey import RSA


class Identity(object):
    '''represents an RSA key pair'''
    def __init__(self, id_rsa_path, id_rsa_pub_path, rsa_key_len):
        self.id_rsa_path = id_rsa_path
        self.id_rsa_pub_path = id_rsa_pub_path
        self.rsa_key_len = rsa_key_len
        self.private_key = None
        self.public_key = None

    def init(self):
        if not os.path.exists(self.id_rsa_path) or not os.path.exists(self.id_rsa_pub_path):
            self.generate_keys()
        else:
            with open(self.id_rsa_pub_path, 'rb') as id_rsa_pub:
                self.public_key = RSA.importKey(id_rsa_pub.read())
            with open(self.id_rsa_path, 'rb') as id_rsa:
                self.private_key = RSA.importKey(id_rsa.read())

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
        if not os.path.exists(os.path.dirname(id_rsa_path)):
            os.makedirs(os.path.dirname(id_rsa_path))
        logger.info('Generating a %d bit RSA key pair...', self.rsa_key_len)
        keys = RSA.generate(self.rsa_key_len)
        with open(id_rsa_pub_path, 'wb') as id_rsa_pub:
            id_rsa_pub.write(keys.publickey().exportKey())
        with open(id_rsa_path, 'wb') as id_rsa:
            id_rsa.write(keys.exportKey())
        self.private_key = keys
        self.public_key = keys.publickey()

    def get_fingerprint(self):
        assert self.public_key
        pk_hash = hashlib.new(self.config.hash_algo)
        pk_hash.update(self.public_key.exportKey('DER'))
        return pk_hash.hexdigest()[:self.config.fingerprint_length]
