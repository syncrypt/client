import sys

import asyncio
from syncrypt import Vault
from syncrypt.backends.binary import BinaryStorageBackend

vault = Vault(sys.argv[1])

@asyncio.coroutine
def upload_all_bundles():
    backend = BinaryStorageBackend(vault)
    yield from backend.open()

    for bundle in vault.walk():
        print(str(bundle))
        yield from backend.upload(bundle)

loop = asyncio.get_event_loop()
loop.run_until_complete(upload_all_bundles())
loop.close()
