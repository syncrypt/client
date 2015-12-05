import argparse
import logging
import os.path
import sys

import asyncio
from syncrypt import Vault
from syncrypt.app import SyncryptApp

COMMANDS = ['pull', 'push', 'watch']

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser(description='Run Syncrypt client')
parser.add_argument('command', metavar='cmd', type=str,
        choices=COMMANDS, help='Command to run: ' + ', '.join(COMMANDS))
parser.add_argument('-d', metavar='DIRECTORY', type=str, default='.',
        dest='directory', help='directory (default: .)')

config = parser.parse_args()

vault = Vault(config.directory)
app = SyncryptApp(vault)
loop = asyncio.get_event_loop()

if config.command == 'watch':
    asyncio.ensure_future(app.start())
    loop.run_forever()
elif config.command == 'pull':
    loop.run_until_complete(app.pull())
elif config.command == 'push':
    loop.run_until_complete(app.push())

loop.close()
