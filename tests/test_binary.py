import unittest
from syncrypt import Vault, Bundle
from syncrypt.backends import LocalStorageBackend, BinaryStorageBackend

class BinaryServerTests(unittest.TestCase):
    def test_vault(self):
        vault = Vault('tests/testvault2')

        backend = vault.backend

        self.assertEqual(type(backend), BinaryStorageBackend)

        self.assertEqual(len(list(vault.walk())), 3)

if __name__ == '__main__':
    unittest.main()
