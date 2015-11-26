import unittest
from syncrypt import Vault, Bundle
from syncrypt.backends import LocalStorageBackend, BinaryStorageBackend

class TestVault(unittest.TestCase):
    def test_vault(self):
        vault = Vault('tests/testvault1')

        backend = vault.get_backend_instance()

        self.assertEqual(type(backend), LocalStorageBackend)

        self.assertEqual(len(list(vault.walk())), 3)


class TestLiveServer(unittest.TestCase):
    def test_vault(self):
        vault = Vault('tests/testvault2')

        backend = vault.get_backend_instance()

        self.assertEqual(type(backend), BinaryStorageBackend)

        self.assertEqual(len(list(vault.walk())), 3)


if __name__ == '__main__':
    unittest.main()
