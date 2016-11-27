import os
import asyncio
import os.path

import asynctest
from syncrypt.models import Identity
from syncrypt.config import AppConfig
from .base import VaultTestCase

__all__ = ('IdentityTests',)

class IdentityTests(VaultTestCase):

    @asyncio.coroutine
    def test_creation(self):

        key = os.path.join(self.working_dir, 'id_rsa')
        key_pub = os.path.join(self.working_dir, 'id_rsa.pub')

        if os.path.exists(key): os.unlink(key)
        if os.path.exists(key_pub): os.unlink(key_pub)

        identity = Identity(key, key_pub, AppConfig())
        yield from identity.init()

        fp = identity.get_fingerprint()
        self.assertEqual(len(fp), 16)

        identity2 = Identity(key, key_pub, AppConfig())
        yield from identity2.init()

        self.assertEqual(fp, identity2.get_fingerprint())
        self.assertEqual(identity2.key_size(), 4096)

    @asyncio.coroutine
    def test_async_key_generation(self):
        'check wether key generation can happen concurrently'

        key = os.path.join(self.working_dir, 'id_rsa')
        key_pub = os.path.join(self.working_dir, 'id_rsa.pub')

        if os.path.exists(key): os.unlink(key)
        if os.path.exists(key_pub): os.unlink(key_pub)

        identity = Identity(key, key_pub, AppConfig())

        loop = asyncio.get_event_loop()

        x = [0]
        @asyncio.coroutine
        def counter():
            while True:
                yield from asyncio.sleep(0.01)
                x[0] += 1

        task = loop.create_task(counter())
        yield from identity.init()
        task.cancel()

        # Make sure the inner loop of counter ran more than 20 times, which
        # assumes that key generation took more than 200 ms
        self.assertGreater(x[0], 20)


