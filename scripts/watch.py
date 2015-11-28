import logging
import os.path
import sys

import asyncio
from hachiko.hachiko import AIOEventHandler, AIOWatchdog
from syncrypt import Vault

logger = logging.getLogger(__name__)

class VaultEventHandler(AIOEventHandler):
    def __init__(self, vault):
        self.vault = vault
        super(VaultEventHandler, self).__init__()

    @asyncio.coroutine
    def on_modified(self, event):
        bundle = vault.bundle_for(os.path.relpath(event.src_path, vault.folder))
        if not bundle is None:
            bundle.schedule_update()

@asyncio.coroutine
def watch_vault(vault):
    logger.info('Watching %s', os.path.abspath(vault.folder))
    watch = AIOWatchdog(vault.folder, event_handler=VaultEventHandler(vault))
    watch.start()
    #watch.stop()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    vault = Vault(sys.argv[1])
    loop = asyncio.get_event_loop()
    asyncio.ensure_future(watch_vault(vault))
    loop.run_forever()
    loop.close()

