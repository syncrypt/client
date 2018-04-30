import asyncio
import hashlib
import logging
import os
import os.path
import zipfile
from enum import Enum
from io import BytesIO

import Cryptodome.Util.number
from Cryptodome.PublicKey import RSA

from syncrypt.pipes import Once
from syncrypt.exceptions import IdentityError, IdentityNotInitialized, IdentityStateError

logger = logging.getLogger(__name__)


class IdentityState(Enum):
    UNINITIALIZED = "uninitialized"
    INITIALIZING = "initializing"
    INITIALIZED = "initialized"


class Identity(object):
    '''represents an RSA key pair'''

    def __init__(self, id_rsa_path, id_rsa_pub_path, config):
        self.id_rsa_path = id_rsa_path
        self.id_rsa_pub_path = id_rsa_pub_path
        self.config = config
        self.state = IdentityState.UNINITIALIZED

    @classmethod
    def from_key(cls, key, config, private_key=None):
        identity = cls(None, None, config)
        identity._keypair = (
            RSA.importKey(key), RSA.importKey(private_key) if private_key else None
        )
        identity.state = IdentityState.INITIALIZED
        return identity

    @property
    def private_key(self):
        try:
            return self._keypair[1]

        except AttributeError:
            try:
                self.read()
                return self._keypair[1]

            except IdentityError:
                return None

    @property
    def public_key(self):
        try:
            return self._keypair[0]

        except AttributeError:
            try:
                self.read()
                return self._keypair[0]

            except IdentityError:
                return None

    def read(self):
        if self.state == IdentityState.INITIALIZING:
            raise IdentityStateError()

        if not os.path.exists(self.id_rsa_path) or not os.path.exists(
            self.id_rsa_pub_path
        ):
            self.state = IdentityState.UNINITIALIZED
            raise IdentityNotInitialized()

        with open(self.id_rsa_pub_path, 'rb') as id_rsa_pub:
            public_key = RSA.importKey(id_rsa_pub.read())
        with open(self.id_rsa_path, 'rb') as id_rsa:
            private_key = RSA.importKey(id_rsa.read())
        self._keypair = (public_key, private_key)
        self.state = IdentityState.INITIALIZED

    def key_size(self):
        return Cryptodome.Util.number.size(self.private_key.n)

    async def init(self):
        if os.path.exists(self.id_rsa_path) and os.path.exists(self.id_rsa_pub_path):
            self.read()

    def is_initialized(self):
        return self.state == IdentityState.INITIALIZED

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

    async def generate_keys(self):
        if self.state != IdentityState.UNINITIALIZED:
            raise IdentityStateError()
        self.state = IdentityState.INITIALIZING

        def _generate():
            if not os.path.exists(os.path.dirname(self.id_rsa_path)):
                os.makedirs(os.path.dirname(self.id_rsa_path))
            logger.info('Generating a %d bit RSA key pair...', self.config.rsa_key_len)
            keys = RSA.generate(self.config.rsa_key_len)
            logger.debug('Finished generating RSA key pair.')
            with open(self.id_rsa_pub_path, 'wb') as id_rsa_pub:
                id_rsa_pub.write(keys.publickey().exportKey())
            with open(self.id_rsa_path, 'wb') as id_rsa:
                id_rsa.write(keys.exportKey())
            self._keypair = (keys.publickey(), keys)
            assert self._keypair[0] is not None

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _generate)

        self.state = IdentityState.INITIALIZED

    def assert_initialized(self):
        if not self.is_initialized():
            raise IdentityNotInitialized()

    def get_fingerprint(self):
        self.assert_initialized()

        assert self.public_key
        pk_hash = hashlib.new(self.config.hash_algo)
        pk_hash.update(self.public_key.exportKey('DER'))
        return pk_hash.hexdigest()[:self.config.fingerprint_length]

    def package_info(self):
        '''
        return a pipe that will contain the identity info such as private and public key
        '''
        memview = BytesIO()
        zipf = zipfile.ZipFile(memview, 'w', zipfile.ZIP_DEFLATED)

        # include private and public key
        def include(f):
            zipf.write(f, arcname=os.path.basename(f))

        include(self.id_rsa_path)
        include(self.id_rsa_pub_path)
        zipf.close()
        memview.seek(0)
        return Once(memview.read())

    def import_from_package(self, filename):
        with zipfile.ZipFile(filename, 'r') as package:
            with open(self.id_rsa_path, 'wb') as f:
                f.write(package.read('id_rsa'))
            with open(self.id_rsa_pub_path, 'wb') as f:
                f.write(package.read('id_rsa.pub'))
        self.read()

