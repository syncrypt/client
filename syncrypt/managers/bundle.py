import logging
import os.path

from sqlalchemy.orm.exc import NoResultFound

from syncrypt.models import Bundle, Vault, store

logger = logging.getLogger(__name__)

class BundleManager:
    model = Bundle

    def __init__(self, app):
        self.app = app

    async def download_bundles_for_vault(self, vault):
        """return an iterator of all bundles in the vault that possible require download"""
        with store.session() as session:
            lst = list(session.query(Bundle).filter(Bundle.vault==vault).all())
            for bundle in lst:
                bundle.vault = vault
            return lst

    #def find_for_vault(self, vault: Vault):
    #    return self.download_bundles_for_vault(vault)

    async def delete_for_vault(self, vault: Vault) -> None:
        with store.session() as session:
            session.query(self.model).filter(self.model.vault_id == vault.id).delete()

    async def get_bundle(self, vault: Vault, path: str) -> Bundle:
        """return an iterator of all bundles in the vault that possible require download"""
        relpath = os.path.relpath(path, vault.folder)
        with store.session() as session:
            try:
                return session.query(Bundle).filter(Bundle.vault==vault,
                        Bundle.relpath==relpath).one()
            except NoResultFound:
                raise FileNotFoundError(
                    'No file with path "{0}" exists in {1}'.format(relpath, vault)
                )
