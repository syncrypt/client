import asyncio
import logging
from getpass import getpass

import syncrypt
from syncrypt.app.auth import AuthenticationProvider

from ..utils.updates import is_update_available
from .syncrypt import SyncryptApp

logger = logging.getLogger(__name__)


class CLIAuthenticationProvider(AuthenticationProvider):

    @asyncio.coroutine
    def get_auth(self, backend):
        username = None
        while not username:
            username = input('Email: ')
        password = getpass()
        return username, password

class CLISyncryptApp(SyncryptApp):

    @asyncio.coroutine
    def check_update(self):
        logger.debug('Retrieving available version...')
        can_update, available = yield from is_update_available()
        print('Installed:   {0}'.format(syncrypt.__version__))
        print('Available:   {0}'.format(available))
        if can_update:
            print('\nAn update to version {0} is available, please download it at'.format(available))
            print('\thttp://alpha.syncrypt.space/releases/')
        else:
            print('\nYou are up to date.')

    @asyncio.coroutine
    def clone_by_name(self, vault_name, local_directory):

        logger.info('Trying to find vault with name "%s"...', vault_name)
        vault_id = None
        for (vid, name) in (yield from self._list_vaults_with_name()):
            vault_id = vid
            if name == vault_name:
                break
            vault_id = None

        if vault_id:
            vault = yield from self.clone(vault_id, local_directory)
        else:
            logger.error('No vault found with name "%s"', vault_name)
            vault = None

        return vault

    @asyncio.coroutine
    def list_keys(self, user=None, with_art=False):
        backend = yield from self.open_backend()
        key_list = (yield from backend.list_keys(user))
        self.print_key_list(key_list, with_art=with_art)
        yield from backend.close()

    def print_key_list(self, key_list, with_art=False):
        for key in key_list:
            fingerprint = key['fingerprint']
            description = key['description']
            created_at = key['created_at']
            if with_art:
                print(draw_art(None, '1', fingerprint))
            print("{0:24}\t{1}\t{2}".format(format_fingerprint(fingerprint), description, created_at))

    @asyncio.coroutine
    def info(self):
        for (index, vault) in enumerate(self.vaults):
            yield from self.retrieve_metadata(vault)
            remote_size = yield from self.get_remote_size_for_vault(vault)
            print("="*78, end='\n\n')
            print("Vault {0}".format(index + 1))
            print()
            print(draw_art(None, '1', vault.identity.get_fingerprint()))
            print()
            print("Vault name:       \t{0}".format(vault.config.vault.get('name', 'Unnamed')))
            print("Vault ID:         \t{0}".format(vault.config.id))
            print("Vault revision:   \t{0}".format(vault.revision or '?'))
            print("Vault fingerprint:\t{0}".format(format_fingerprint(
                    vault.identity.get_fingerprint())))
            print("Local directory:  \t{0}".format(os.path.abspath(vault.folder)))
            print("Local size:       \t{0} (includes metadata)".format(format_size(
                    vault.get_local_size())))
            print("Remote size:      \t{0} (includes versioned copies)".format(format_size(
                    remote_size)))
            print("Your fingerprint: \t{0}".format(format_fingerprint(
                    self.identity.get_fingerprint())))
            print()
        print("="*78)

    @asyncio.coroutine
    def add_user(self, email):
        vault = self.vaults[0]
        yield from vault.backend.open()
        logger.info('Adding user "%s" to %s', email, vault)
        yield from vault.backend.add_vault_user(email)

        key_list = yield from vault.backend.list_keys(email)
        key_list = list(key_list)

        self.print_key_list(key_list)
        print('\nPlease verify the above keys.')
        yesno = input('Do you really want to send the keys to all of the fingerprints listed above? [y/N] ')

        if yesno in ('y', 'Y'):
            for key in key_list:
                # retrieve key and verify fingerrint
                fingerprint = key['fingerprint']
                public_key = key['public_key']
                identity = Identity.from_key(public_key, vault.config)
                assert identity.get_fingerprint() == fingerprint
                yield from self.add_user_vault_key(vault, email, identity)

    @asyncio.coroutine
    def print_list_of_vaults(self):
        for (vault_id, name) in (yield from self._list_vaults_with_name()):
            print("{0} {1}".format(vault_id, name))

    @asyncio.coroutine
    def print_list_of_all_vaults(self):
        backend = yield from self.open_backend()
        for vault in (yield from backend.list_vaults()):
            logger.debug("Received vault: %s", vault)
            size, size_unit = size_with_unit(vault['byte_size'])
            fmt_str = "{0} | Users: {1:2} | Files: {2:4} | Revisions: {3:4} | Size: {4:8} {5}".format(
                vault['id'].decode('utf-8'),
                vault['user_count'],
                vault['file_count'],
                vault['revision_count'],
                size,
                size_unit
            )
            print(fmt_str)
        yield from backend.close()

    @asyncio.coroutine
    def print_log(self, verbose=False):
        local_tz = get_localzone()
        for vault in self.vaults:
            try:
                yield from vault.backend.open()
            except VaultNotInitialized:
                logger.error('%s has not been initialized. Use "syncrypt init" to register the folder as vault.' % vault)
                continue
            queue = yield from vault.backend.changes(None, None, verbose=verbose)
            while True:
                item = yield from queue.get()
                if item is None:
                    break
                store_hash, metadata, server_info = item
                bundle = VirtualBundle(None, vault, store_hash=store_hash)
                yield from bundle.write_encrypted_metadata(Once(metadata))
                rev_id = server_info['id'].decode(vault.config.encoding)
                created_at = iso8601.parse_date(server_info['created_at'].decode())\
                        .astimezone(local_tz)\
                        .strftime('%x %X')
                operation = server_info['operation'].decode(vault.config.encoding)
                if verbose:
                    user_email = server_info['email'].decode(vault.config.encoding)
                    print("%s | %s | %s | %-9s %s" % (created_at, rev_id, user_email,
                        operation, bundle.relpath))
                else:
                    print("%s | %-9s %s" % (created_at, operation, bundle.relpath))

        yield from self.wait()

