import asyncio
import logging
import os
from getpass import getpass

import iso8601
from tzlocal import get_localzone

import syncrypt
from syncrypt.app.auth import AuthenticationProvider
from syncrypt.models import Identity, VirtualBundle
from syncrypt.pipes import (DecryptRSA_PKCS1_OAEP, EncryptRSA_PKCS1_OAEP, FileWriter, Once,
                            SnappyCompress, StdoutWriter)
from syncrypt.utils.format import format_fingerprint, format_size, size_with_unit
from syncrypt.vendor.keyart import draw_art

from ..exceptions import IdentityNotInitialized, InvalidAuthentification, VaultNotInitialized
from ..utils.updates import is_update_available
from .syncrypt import SyncryptApp

logger = logging.getLogger(__name__)


class CLIAuthenticationProvider(AuthenticationProvider):

    async def get_auth(self, backend):
        username = None
        while not username:
                username = input('Email: ')
        password = getpass()
        return username, password


class SyncryptCLIApp(SyncryptApp):

    def __init__(self, config, **kwargs):
        super(SyncryptCLIApp, self).__init__(config,
                                             auth_provider=CLIAuthenticationProvider(),
                                             **kwargs)

    async def login(self):
        try:
            self.identity.assert_initialized()
        except IdentityNotInitialized:
            print("Your user key hasn't been generated yet. Please either")
            print(" 1) generate a new key with 'syncrypt generate-key'")
            print(" 2) import an existing key with 'syncrypt import-key'")
            return
        # Already logged in?
        try:
            backend = await self.open_backend(num_tries=1)
            await backend.close()
            print("Already logged in.")
        except InvalidAuthentification as e:
            backend = await self.open_backend(always_ask_for_creds=True)
            await backend.close()
            await self.upload_identity()

    async def register(self):
        #cfg = self.config
        #auth_provider = auth_provider or self.auth_provider

        username = None
        while not username:
            username = input('Email: ')
        firstname = None
        while not firstname:
            firstname = input('First name: ')
        surname = None
        while not surname:
            surname = input('Surname: ')
        password = getpass()
        password_again = getpass('Password (again): ')
        if password != password_again:
            raise ValueError('Passwords do not match')
        await self.signup(username, password, firstname, surname)
        print("Registration successful, please check your inbox for the confirmation mail.")

    async def logout(self):
        with self.config.update_context():
            self.config.update('remote', {'auth': ''})
        print("Removed auth token.")

    async def check_update(self):
        logger.debug('Retrieving available version...')
        can_update, available = await is_update_available()
        print('Installed:   {0}'.format(syncrypt.__version__))
        print('Available:   {0}'.format(available))
        if can_update:
            print('\nAn update to version {0} is available, please download it at'.format(available))
            print('\thttp://alpha.syncrypt.space/releases/')
        else:
            print('\nYou are up to date.')

    async def clone_by_name(self, vault_name, local_directory):

        logger.info('Trying to find vault with name "%s"...', vault_name)
        vault_id = None
        for (vid, name) in (await self._list_vaults_with_name()):
            vault_id = vid
            if name == vault_name:
                break
            vault_id = None

        if vault_id:
            vault = await self.clone(vault_id, local_directory)
        else:
            logger.error('No vault found with name "%s"', vault_name)
            vault = None

        return vault

    async def list_keys(self, user=None, with_art=False):
        backend = await self.open_backend()
        key_list = (await backend.list_keys(user))
        self.print_key_list(key_list, with_art=with_art)
        await backend.close()

    def print_key_list(self, key_list, with_art=False):
        for key in key_list:
            fingerprint = key['fingerprint']
            description = key['description']
            created_at = key['created_at']
            if with_art:
                print(draw_art(None, '1', fingerprint))
            print("{0:24}\t{1}\t{2}".format(format_fingerprint(fingerprint), description, created_at))

    async def info(self):
        for (index, vault) in enumerate(self.vaults):
            await self.retrieve_metadata(vault)
            remote_size = await self.get_remote_size_for_vault(vault)
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

    async def add_user(self, email):
        vault = self.vaults[0]
        await vault.backend.open()
        logger.info('Adding user "%s" to %s', email, vault)
        await vault.backend.add_vault_user(email)

        key_list = await vault.backend.list_keys(email)
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
                await self.add_user_vault_key(vault, email, identity)

    async def print_list_of_vaults(self):
        for (vault_id, name) in (await self._list_vaults_with_name()):
            print("{0} {1}".format(vault_id, name))

    async def print_list_of_all_vaults(self):
        backend = await self.open_backend()
        for vault in (await backend.list_vaults()):
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
        await backend.close()

    async def print_log(self, verbose=False):
        local_tz = get_localzone()
        for vault in self.vaults:
            try:
                await vault.backend.open()
            except VaultNotInitialized:
                logger.error('%s has not been initialized. Use "syncrypt init" to register the folder as vault.' % vault)
                continue
            queue = await vault.backend.changes(None, None, verbose=verbose)
            while True:
                item = await queue.get()
                if item is None:
                    break
                store_hash, metadata, server_info = item
                bundle = VirtualBundle(None, vault, store_hash=store_hash)
                await bundle.write_encrypted_metadata(Once(metadata))
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

        await self.wait()

