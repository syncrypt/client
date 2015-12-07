import unittest
import os.path
import shutil
import os

import asyncio
import asynctest
from syncrypt import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend, LocalStorageBackend

class VaultTestCase(asynctest.TestCase):
    folder = None

    def setUp(self):
        #self.loop = asyncio.new_event_loop()
        #asyncio.set_event_loop(self.loop)
        if os.path.exists('tests/testvault'):
            shutil.rmtree('tests/testvault')
        shutil.copytree(self.folder, 'tests/testvault')
        self.vault = Vault('tests/testvault')
        self.loop.run_until_complete(self.vault.backend.wipe())

    #def tearDown(self):
    #    self.loop.close()

