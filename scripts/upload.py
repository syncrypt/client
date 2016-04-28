import logging
import sys

import asyncio
from syncrypt import Vault

@asyncio.coroutine
def update_and_upload(backend, bundle):
    yield from bundle.update()
    yield from backend.stat(bundle)
    if bundle.needs_upload():
        yield from backend.upload(bundle)

@asyncio.coroutine
def upload_all_bundles():
    yield from vault.backend.open()
    yield from asyncio.wait([
        asyncio.ensure_future(update_and_upload(vault.backend, bundle))
            for bundle in vault.walk_disk()])

logging.basicConfig(level=logging.INFO)

vault = Vault(sys.argv[1])

loop = asyncio.get_event_loop()
loop.run_until_complete(upload_all_bundles())
loop.close()
