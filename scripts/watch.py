import logging
import os.path
import sys

import asyncio
from hachiko.hachiko import AIOEventHandler, AIOWatchdog
from syncrypt import Vault

logging.basicConfig(level=logging.INFO)

vault = Vault(sys.argv[1])

class MyEventHandler(AIOEventHandler):
    @asyncio.coroutine
    def on_modified(self, event):
        bundle = vault.bundle_for(os.path.relpath(event.src_path, vault.folder))
        if not bundle is None:
            bundle.schedule_update()

@asyncio.coroutine
def watch_directory(path):
    watch = AIOWatchdog(path, event_handler=MyEventHandler())
    watch.start()
    for _ in range(20):
        yield from asyncio.sleep(100)
    watch.stop()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    asyncio.ensure_future(watch_directory(vault.folder))
    loop.run_forever()
    loop.close()

