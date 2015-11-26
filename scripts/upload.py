import logging
import sys

import asyncio
from syncrypt import Vault

@asyncio.coroutine
def update_and_upload(backend, bundle):
    yield from bundle.update()
    yield from backend.upload(bundle)

@asyncio.coroutine
def upload_all_bundles():
    backend = vault.get_backend_instance()
    yield from backend.open()
    yield from asyncio.wait([
        asyncio.ensure_future(update_and_upload(backend, bundle))
            for bundle in vault.walk()])

logging.basicConfig(level=logging.INFO)

vault = Vault(sys.argv[1])

loop = asyncio.get_event_loop()
loop.run_until_complete(upload_all_bundles())
loop.close()
