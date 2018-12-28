import asyncio
import logging
import os
import os.path
import shutil
import unittest
from glob import glob

import asynctest
import pytest
from hypothesis import example, given, settings, HealthCheck

from syncrypt.app import SyncryptApp
from syncrypt.backends import BinaryStorageBackend
from syncrypt.config import AppConfig
from syncrypt.models import Bundle, Vault
from tests.base import VaultTestCase
from tests.strategies import files

from .base import TestAppConfig


def count_files(folder):
    return len([name for name in os.listdir(folder) if name != '.vault'])


@pytest.mark.requires_server
@pytest.mark.hypothesis
class HypoBinaryTestCase(asynctest.TestCase):
    folder = 'tests/testbinaryempty/'

    @settings(suppress_health_check=HealthCheck.all())
    @given(files(), files())

    # The following example will test "unicode surrogates" in filename and content
    @example([{'filename': 'surrogate\udcfc', 'content': b'surrogate\udcfccontent'}], [])

    def test_initial_and_added(self, initial_files, added_files):
        app_config_file = os.path.join(VaultTestCase.working_dir, 'test_config')
        app = SyncryptApp(TestAppConfig(app_config_file))

        vault_folder = os.path.join(VaultTestCase.working_dir, 'testvault')
        if os.path.exists(vault_folder):
            shutil.rmtree(vault_folder)
        shutil.copytree(self.folder, vault_folder)
        self.vault = Vault(vault_folder)

        async def go():
            vault = self.vault

            for file_info in initial_files:
                p = os.path.join(vault.folder, file_info['filename'])
                with open(p, 'wb') as f:
                    f.write(file_info['content'])

            files_in_old_vault = count_files(vault.folder)
            self.assertEqual(files_in_old_vault, len(initial_files))

            other_vault_path = os.path.join(VaultTestCase.working_dir, 'othervault')

            # remove "other vault" folder first
            if os.path.exists(other_vault_path):
                shutil.rmtree(other_vault_path)

            await app.add_vault(self.vault)

            await app.open_or_init(self.vault)
            await app.push() # init all vaults

            # now we will clone the initialized vault by copying the vault config
            shutil.copytree(os.path.join(self.vault.folder, '.vault'),
                            os.path.join(other_vault_path, '.vault'))
            self.other_vault = Vault(other_vault_path)
            with self.other_vault.config.update_context():
                self.other_vault.config.unset('vault.revision')
                self.other_vault.config.unset('remote.auth')

            await app.add_vault(self.other_vault)

            await app.open_or_init(self.other_vault)
            await app.pull()

            assert not self.vault.active
            assert not self.other_vault.active

            files_in_new_vault = count_files(other_vault_path)
            self.assertEqual(files_in_new_vault, files_in_old_vault)

            for file_info in added_files:
                p = os.path.join(vault.folder, file_info['filename'])
                with open(p, 'wb') as f:
                    f.write(file_info['content'])

            await app.push() # push all vaults

            await app.pull() # pull all vaults

            assert not self.vault.active
            assert not self.other_vault.active

            files_in_new_vault = count_files(other_vault_path)
            final_files = set([f['filename'] for f in initial_files] + [f['filename'] for f in added_files])
            self.assertEqual(files_in_new_vault, len(final_files))

        async def close():
            await app.close()

        self.loop.run_until_complete(app.initialize())
        try:
            self.loop.run_until_complete(go())
        finally:
            self.loop.run_until_complete(close())


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)
    unittest.main()
