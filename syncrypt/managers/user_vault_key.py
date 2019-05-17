import logging

from syncrypt.models import Identity, UserVaultKey, Vault, store

logger = logging.getLogger(__name__)


class UserVaultKeyManager:
    model = UserVaultKey

    def __init__(self, app):
        self.app = app

    def add(self, vault: Vault, user_id: str, identity: Identity):
        with store.session() as session:
            fingerprint = identity.get_fingerprint()
            public_key = identity.public_key.export_key('DER')
            user_vault_key = session.query(UserVaultKey)\
                .filter(self.model.vault_id == vault.id)\
                .filter(self.model.fingerprint == fingerprint)\
                .first()
            if not user_vault_key:
                session.add(self.model(vault_id=vault.id, fingerprint=fingerprint,
                    user_id=user_id, public_key=public_key))
            else:
                if user_vault_key.user_id != user_id or user_vault_key.public_key != public_key:
                    raise ValueError("Attempted to another UserVaultKey with existing fingerprint")

    def list_for_vault(self, vault):
        with store.session() as session:
            return (
                session.query(UserVaultKey)
                .filter(self.model.vault_id == vault.id)
                .all()
            )

    async def delete_for_vault(self, vault: Vault) -> None:
        with store.session() as session:
            session.query(self.model).filter(self.model.vault_id == vault.id).delete()

    def remove(self, vault: Vault, user_id: str, identity: Identity) -> None:
        with store.session() as session:
            session.query(self.model).filter(
                    self.model.vault_id == vault.id,
                    self.model.fingerprint==identity.get_fingerprint(),
                    self.model.user_id==user_id).delete()

    def find_key(self, vault: Vault, fingerprint) -> UserVaultKey:
        with store.session() as session:
            return (
                session.query(UserVaultKey)
                .filter(self.model.vault_id == vault.id)
                .filter(self.model.fingerprint == fingerprint)
                .first()
            )
