import logging
import os.path
from fnmatch import fnmatch

from sqlalchemy import inspect
from sqlalchemy.orm.exc import NoResultFound

from syncrypt.models import Bundle, Vault, store

logger = logging.getLogger(__name__)


class BundleManager:
    model = Bundle

    def __init__(self, app):
        self.app = app

    async def download_bundles_for_vault(self, vault):
        """
        return an iterator of all bundles in the vault that possible require download
        """
        with store.session() as session:
            lst = list(session.query(Bundle).filter(Bundle.vault==vault).all())
            for bundle in lst:
                bundle.vault = vault
                await bundle.update()
                if bundle.remote_hash_differs:
                    session.expunge(bundle)
                    if inspect(vault).session:
                        session.expunge(vault)
                    yield bundle

    def get_bundle_for_relpath(self, relpath, vault):
        # check if path should be ignored
        for filepart in relpath.split("/"): # TODO: use os.path.split to be windows compliant
            if any(fnmatch(filepart, ig) for ig in vault.config.ignore_patterns):
                return None

        if os.path.isdir(os.path.join(vault.folder, relpath)):
            return None

        with store.session() as session:
            try:
                bundle = session.query(Bundle).filter(Bundle.vault==vault,
                        Bundle.relpath==relpath.encode()).one()
                # vault is loaded lazily. We already have the vault
                # object here, so just set it.
                bundle.vault = vault
                return bundle
            except NoResultFound:
                bundle = Bundle(relpath=relpath, vault=vault, vault_id=vault.id)

        bundle = Bundle(relpath=relpath, vault=vault, vault_id=vault.id)
        bundle.update_store_hash()
        return bundle

    async def upload_bundles_for_vault(self, vault):
        """
        return an iterator of all bundles in the vault that require upload
        """
        registered_paths = set()

        if inspect(vault).session:
            raise ValueError('Vault object is bound to a session')

        # First, try to find changes from database to disk
        with store.session() as session:
            lst = list(session.query(Bundle).filter(Bundle.vault==vault).all())
            for bundle in lst:
                bundle.vault = vault
                registered_paths.add(bundle.relpath)
                await bundle.update()
                if bundle.remote_hash_differs:
                    session.expunge(bundle)
                    if inspect(vault).session:
                        session.expunge(vault)
                    yield bundle

            if inspect(vault).session:
                session.expunge(vault)

            # Next, we will walk the disk to find new bundles
            async def walk_disk(subfolder=None):
                folder = vault.folder
                if subfolder:
                    folder = os.path.join(folder, subfolder)
                for file in os.listdir(folder):
                    if any(fnmatch(file, ig) for ig in vault.config.ignore_patterns):
                        continue
                    abspath = os.path.join(folder, file)
                    relpath = os.path.relpath(abspath, vault.folder)
                    #logger.debug("%s, %s", abspath, registered_paths)
                    if relpath in registered_paths:
                        continue
                    if os.path.isdir(abspath):
                        async for bundle in walk_disk(subfolder=relpath):
                            yield bundle
                    else:
                        yield self.get_bundle_for_relpath(relpath, vault)

            async for bundle in walk_disk():
                await bundle.update()
                yield bundle

    #def find_for_vault(self, vault: Vault):
    #    return self.download_bundles_for_vault(vault)

    async def delete_for_vault(self, vault: Vault) -> None:
        with store.session() as session:
            session.query(self.model).filter(self.model.vault_id == vault.id).delete()

    async def get_bundle_by_hash(self, vault: Vault, store_hash) -> Bundle:
        with store.session() as session:
            try:
                bundle = session.query(Bundle).filter(Bundle.vault==vault,
                        Bundle.store_hash==store_hash).one()
                # vault is loaded lazily. We already have the vault
                # object here, so just set it.
                # bundle.vault = vault
                return bundle
            except NoResultFound:
                raise FileNotFoundError(
                    'No file with hash "{0}" exists in {1}'.format(store_hash, vault)
                )

    async def get_bundle(self, vault: Vault, path: str) -> Bundle:
        relpath = os.path.relpath(path, vault.folder)
        with store.session() as session:
            try:
                bundle = session.query(Bundle).filter(Bundle.vault==vault,
                        Bundle.relpath==relpath.encode()).one()
                # vault is loaded lazily. We already have the vault
                # object here, so just set it.
                bundle.vault = vault
                return bundle
            except NoResultFound:
                raise FileNotFoundError(
                    'No file with path "{0}" exists in {1}'.format(relpath, vault)
                )
