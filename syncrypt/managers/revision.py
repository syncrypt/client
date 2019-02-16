import logging
from sqlalchemy import inspect
from typing import Sequence

import smokesignal
from sqlalchemy.orm.exc import NoResultFound

from syncrypt.exceptions import InvalidRevision, UnexpectedParentInRevision
from syncrypt.models import (Bundle, Identity, Revision, RevisionOp, UserVaultKey, Vault, VaultUser,
                             store)
from syncrypt.pipes import Once

logger = logging.getLogger(__name__)


class RevisionManager:
    model = Revision

    def __init__(self, app):
        self.app = app

    def get_or_create_by_id(self, session, id):
        try:
            return session.query(self.model).filter(self.model.id == id).one()
        except NoResultFound:
            return self.model(id=id)

    def list_for_vault(self, vault: Vault) -> Sequence[Revision]:
        with store.session() as session:
            return (
                session.query(Revision).filter(Revision.local_vault_id == vault.id).all()
            )

    async def delete_for_vault(self, vault: Vault) -> None:
        with store.session() as session:
            session.query(Revision).filter(Revision.local_vault_id == vault.id).delete()

    async def apply(self, revision: Revision, vault: Vault):
        if inspect(vault).session:
            raise ValueError('Vault object is bound to a session')

        revision.assert_valid()

        # 1. Check preconditions for this to be a valid revision (current revision must be parent)
        if vault.revision != revision.parent_id:
            raise UnexpectedParentInRevision("Expected parent to be {0}, but is {1}"\
                    .format(revision.parent_id, vault.revision))

        smokesignal.emit('pre_apply_revision', vault=vault, revision=revision)

        with store.session() as session:
            # 2. Check if signing user's key is in the user vault key list
            if revision.operation != RevisionOp.CreateVault:
                signer_key = self.app.user_vault_keys.find_key(
                    vault, revision.user_fingerprint
                )
                if not signer_key:
                    raise InvalidRevision(
                        "Key {0} is not allowed to generate revisions for vault {1}"
                            .format(revision.user_fingerprint, vault)
                    )
            else:
                # CreateVault is the only operation that is allowed to provide its own key
                signer_key = UserVaultKey(
                    vault_id=vault.id,
                    user_id=revision.user_id,
                    fingerprint=revision.user_fingerprint,
                    public_key=revision.user_public_key,
                )

            # 3. Verify revision signature
            revision.verify(signer_key.get_identity(self.app.config))

            # 4. Based on the revision type, perform an action to our state of the vault
            logger.debug(
                "Applying %s (%s) to %s",
                revision.operation,
                revision.revision_id,
                vault.id,
            )

            if revision.operation == RevisionOp.CreateVault:
                session.add(vault)
                session.add(signer_key)
                session.add(VaultUser(vault_id=vault.id, user_id=revision.user_id))
                session.commit()
            elif revision.operation == RevisionOp.Upload:
                try:
                    bundle = await self.app.bundles.get_bundle_by_hash(vault, revision.file_hash)
                    session.delete(bundle)
                except FileNotFoundError:
                    pass
                bundle = await self.create_bundle_from_revision(revision, vault)
                session.add(bundle)
                session.commit()
                revision.path = bundle.relpath
            elif revision.operation == RevisionOp.SetMetadata:
                await vault.write_encrypted_metadata(Once(revision.revision_metadata))
            elif revision.operation == RevisionOp.RemoveFile:
                bundle = await self.app.bundles.get_bundle_by_hash(vault, revision.file_hash)
                session.delete(bundle)
                session.commit()
                revision.path = bundle.relpath
            elif revision.operation == RevisionOp.AddUser:
                self.app.vault_users.add(vault, revision.user_id)
            elif revision.operation == RevisionOp.RemoveUser:
                self.app.vault_users.remove(vault, revision.user_id)
            elif revision.operation == RevisionOp.AddUserKey:
                new_identity = Identity.from_key(revision.user_public_key, self.app.config)
                self.app.user_vault_keys.add(vault, revision.user_id, new_identity)
            elif revision.operation == RevisionOp.RemoveUserKey:
                new_identity = Identity.from_key(revision.user_public_key, self.app.config)
                self.app.user_vault_keys.remove(vault, revision.user_id, new_identity)
            else:
                raise NotImplementedError(revision.operation)

            # 5. Store the revision in config and db
            revision.local_vault_id = vault.id
            revision.creator_id = signer_key.user_id
            session.add(revision)
            session.commit()
            vault.revision_count = (
                session.query(Revision)
                .filter(Revision.local_vault_id == vault.id)
                .count()
            )
            if revision.operation in (RevisionOp.Upload, RevisionOp.RemoveFile):
                vault.file_count = (
                    session.query(Bundle)
                    .filter(Bundle.vault_id == vault.id)
                    .count()
                )
            if revision.operation in (RevisionOp.CreateVault, RevisionOp.AddUser, RevisionOp.RemoveUser):
                vault.user_count = (
                    session.query(VaultUser)
                    .filter(VaultUser.vault_id == vault.id)
                    .count()
                )
            vault.modification_date = revision.created_at
            logger.debug("Vault state revision_count=%s file_count=%s user_count=%s",
                    vault.revision_count, vault.file_count, vault.user_count)
            # vault.revision = revision.id
            session.add(vault)
            vault.update_revision(revision)
            session.commit()

        smokesignal.emit('post_apply_revision', vault=vault, revision=revision)

    async def create_bundle_from_revision(self, revision, vault):
        bundle = Bundle(vault=vault, store_hash=revision.file_hash)
        metadata = await bundle.decrypt_metadata(revision.revision_metadata)
        bundle.relpath = metadata["filename"]
        bundle.hash = revision.crypt_hash
        bundle.key = metadata["key"]
        return bundle
