import logging
import os

import asyncio
from hachiko.hachiko import AIOEventHandler, AIOWatchdog

logger = logging.getLogger(__name__)

def create_watchdog(app, vault):
    return AIOWatchdog(vault.folder, event_handler=VaultEventHandler(app, vault))

class VaultEventHandler(AIOEventHandler):
    '''
    A watchdog wrapper that will report file changes back to the syncrypt
    controller app.
    '''

    def __init__(self, app, vault):
        self.app = app
        self.vault = vault
        super(VaultEventHandler, self).__init__()

    @asyncio.coroutine
    def on_file_changed(self, path):
        bundle = self.vault.bundle_for(os.path.relpath(path, self.vault.folder))
        if not bundle is None:
            logger.info('File creation detected (%s)', bundle)
            self.app.schedule_update(bundle)
        else:
            logger.debug('Ignoring file creation: %s', path)

    @asyncio.coroutine
    def on_file_removed(self, path):
        bundle = self.vault.bundle_for(os.path.relpath(path, self.vault.folder))
        if not bundle is None:
            logger.info('File delete detected (%s)', bundle)
        else:
            logger.debug('Ignoring file delete: %s', path)

    @asyncio.coroutine
    def on_deleted(self, event):
        yield from self.on_file_removed(event.dest_path)

    @asyncio.coroutine
    def on_moved(self, event):
        yield from self.on_file_changed(event.dest_path)
        yield from self.on_file_removed(event.src_path)

    @asyncio.coroutine
    def on_created(self, event):
        yield from self.on_file_changed(event.src_path)

    @asyncio.coroutine
    def on_modified(self, event):
        yield from self.on_file_changed(event.src_path)
