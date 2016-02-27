
import os
import os.path
import shutil
import unittest

import asyncio
from glob import glob
import asynctest
from base import VaultTestCase
from common import CommonTestsMixin
from hypothesis import example, given
from tests.strategies import vault
from syncrypt import Bundle, Vault
from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend
from syncrypt.config import VaultConfig


class HypoBinaryTestCase(VaultTestCase):
    folder = 'tests/testbinaryempty/'

    @given(vault())
    def test_two_local_one_remote_hypo(self, vault_info):
        app = SyncryptApp(VaultConfig())

        self.setUp()

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
            print ("ppp", glob(os.path.join(other_vault_path, '*')))
            self.assertEqual(files_in_new_vault, len(vault_info))

        @asyncio.coroutine
        def wait():
            yield from app.wait()

        self.loop.run_until_complete(go())
        self.loop.run_until_complete(wait())


if __name__ == '__main__':
    unittest.main()
