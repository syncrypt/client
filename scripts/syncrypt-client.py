import logging
import os.path
import sys

import asyncio
from syncrypt import Vault
from syncrypt.app import SyncryptApp

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    vault = Vault(sys.argv[1])
    app = SyncryptApp(vault)
    loop = asyncio.get_event_loop()
    asyncio.ensure_future(app.start())
    loop.run_forever()
    loop.close()

