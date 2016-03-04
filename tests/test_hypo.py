
import logging
import os
import os.path
import shutil
import unittest
from glob import glob

import asyncio
import asynctest
from hypothesis import example, given, settings
from syncrypt import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend
from syncrypt.config import VaultConfig
from tests.base import VaultTestCase
from tests.common import CommonTestsMixin
from tests.strategies import vault


class HypoBinaryTestCase(asynctest.TestCase):
    folder = 'tests/testbinaryempty/'

    @settings(timeout=30)
    @given(vault())
    def test_two_local_one_remote_hypo(self, vault_info):
        app = SyncryptApp(VaultConfig())

        if os.path.exists('tests/testvault'):
            shutil.rmtree('tests/testvault')
        shutil.copytree(self.folder, 'tests/testvault')
        self.vault = Vault('tests/testvault')

        @asyncio.coroutine
        def go():
            vault = self.vault

            for file_info in vault_info:
                p = os.path.join(vault.folder, file_info['filename'])
                with open(p, 'wb') as f:
                    f.write(file_info['content'])

            other_vault_path = 'tests/othervault'

            # remove "other vault" folder first
            if os.path.exists(other_vault_path):
                shutil.rmtree(other_vault_path)

            app.add_vault(self.vault)

            #yield from app.init() # init all vaults
            yield from app.push() # init all vaults

            # now we will clone the initialized vault by copying the vault config
            shutil.copytree(os.path.join(self.vault.folder, '.vault'),
                            os.path.join(other_vault_path, '.vault'))
            self.other_vault = Vault(other_vault_path)

            app.add_vault(self.other_vault)

            yield from app.pull()

            assert not self.vault.active
            assert not self.other_vault.active

            files_in_new_vault = len(glob(os.path.join(other_vault_path, '*')))
            self.assertEqual(files_in_new_vault, len(vault_info))

        @asyncio.coroutine
        def close():
            yield from app.close()

        try:
            self.loop.run_until_complete(go())
        finally:
            self.loop.run_until_complete(close())


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)
    unittest.main()
