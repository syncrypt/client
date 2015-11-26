import unittest
from syncrypt import Vault, Bundle

class TestVault(unittest.TestCase):
    def test_vault(self):
        vault = Vault('tests/testvault1')

        backend = vault.get_backend_instance()


if __name__ == '__main__':
    unittest.main()
