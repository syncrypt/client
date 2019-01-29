import trio
import os
import os.path

import pytest

from syncrypt.config import AppConfig
from syncrypt.models import Identity

from .base import VaultTestCase


@pytest.mark.slow
async def test_creation():

    key = os.path.join(self.working_dir, "id_rsa")
    key_pub = os.path.join(self.working_dir, "id_rsa.pub")

    if os.path.exists(key):
        os.unlink(key)
    if os.path.exists(key_pub):
        os.unlink(key_pub)

    identity = Identity(key, key_pub, AppConfig())
    await identity.init()
    await identity.generate_keys()

    fp = identity.get_fingerprint()
    assert len(fp) == 16

    identity2 = Identity(key, key_pub, AppConfig())
    await identity2.init()

    assert fp == identity2.get_fingerprint()
    assert identity2.key_size() == 4096


@pytest.mark.slow
async def test_async_key_generation():
    "check wether key generation can happen concurrently"

    key = os.path.join(self.working_dir, "id_rsa")
    key_pub = os.path.join(self.working_dir, "id_rsa.pub")

    if os.path.exists(key):
        os.unlink(key)
    if os.path.exists(key_pub):
        os.unlink(key_pub)

    identity = Identity(key, key_pub, AppConfig())

    loop = asyncio.get_event_loop()

    x = [0]

    async def counter():
        while True:
            await asyncio.sleep(0.001)
            x[0] += 1

    await identity.init()
    task = loop.create_task(counter())
    await identity.generate_keys()
    task.cancel()

    # Make sure the inner loop of counter ran more than 20 times, which
    # assumes that key generation took more than 20 ms
    assert x[0] > 20


@pytest.mark.slow
async def test_signing():
    "test our sign and verify functions"

    key = os.path.join(self.working_dir, "id_rsa")
    key_pub = os.path.join(self.working_dir, "id_rsa.pub")

    if os.path.exists(key):
        os.unlink(key)
    if os.path.exists(key_pub):
        os.unlink(key_pub)

    identity = Identity(key, key_pub, AppConfig())
    await identity.init()
    await identity.generate_keys()

    signature = identity.sign(b'I did say that.')

    assert identity.verify(b'I did say that.', signature)
    assert not identity.verify(b'I did not say that.', signature)
