import os
import os.path

import asynctest
from syncrypt.identity import Identity
from syncrypt.config import Config
from .base import VaultTestCase

__all__ = ('IdentityTests',)

class IdentityTests(VaultTestCase):

    @asynctest.ignore_loop
    def test_creation(self):

        config = Config()

        identity = Identity(os.path.join(self.working_dir, 'id_rsa'),
            os.path.join(self.working_dir, 'id_rsa.pub'),
            config)
        identity.init()

        fp = identity.get_fingerprint()
        self.assertEqual(len(fp), 16)

        identity2 = Identity(os.path.join(self.working_dir, 'id_rsa'),
            os.path.join(self.working_dir, 'id_rsa.pub'),
            config)
        identity2.init()

        self.assertEqual(fp, identity2.get_fingerprint())
        self.assertEqual(identity2.key_size(), 4096)
