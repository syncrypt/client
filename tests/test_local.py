import unittest
from syncrypt import Vault, Bundle
from syncrypt.backends import LocalStorageBackend

class LocalStorageTests(unittest.TestCase):
    def test_vault(self):
        vault = Vault('tests/testvault1')

        self.assertEqual(type(vault.backend), LocalStorageBackend)

        self.assertEqual(len(list(vault.walk())), 3)

if __name__ == '__main__':
    unittest.main()
