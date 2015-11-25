import logging
import sys

import asyncio
from syncrypt import Vault

@asyncio.coroutine
def upload_all_bundles():
    backend = vault.get_backend_instance()
    yield from backend.open()

    for bundle in vault.walk():
        print(str(bundle))
        yield from backend.upload(bundle)

logging.basicConfig(level=logging.INFO)

vault = Vault(sys.argv[1])

loop = asyncio.get_event_loop()
loop.run_until_complete(upload_all_bundles())
loop.close()
