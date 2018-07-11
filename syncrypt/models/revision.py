import enum

from sqlalchemy import (Binary, Column, DateTime, Enum, ForeignKey, Integer, LargeBinary, String,
                        UniqueConstraint)

from syncrypt.exceptions import InvalidRevision

from .base import Base
from .identity import Identity


class RevisionOp(enum.Enum):
    CreateVault = "OP_CREATE_VAULT"
    Upload = "OP_UPLOAD"
    # ^ rename to OP_INSERT_FILE or so to be consistent with OP_DELETE_FILE?
    SetMetadata = "OP_SET_METADATA"
    DeleteFile = "OP_DELETE_FILE"
    RenameFile = "OP_RENAME_FILE"


class Revision(Base):
    __tablename__ = "revision"
    __table_args__ = (
        UniqueConstraint("revision_id", "local_vault_id", name="revision_vault_uniq"),
    )

    # These are for local management
    id = Column(Integer(), primary_key=True)
    local_vault_id = Column(String(128), ForeignKey("vault.id"))

    revision_id = Column(String(128))
    parent_id = Column(String(128), ForeignKey("revision.revision_id"), nullable=True)
    vault_id = Column(String(128))

    # These are the core fields that every revision has to have.
    operation = Column(Enum(RevisionOp, values_callable=lambda x: [e.value for e in x]))
    created_at = Column(DateTime())
    user_id = Column(String(250))
    user_fingerprint = Column(String(64))
    signature = Column(Binary(512))

    # Additional fields for OP_CREATE_VAULT
    nonce = Column(Integer(), nullable=True)
    public_key = Column(Binary(4096), nullable=True)

    # Additional fields for OP_UPLOAD
    file_hash = Column(String(250), nullable=True)
    path = Column(String(255), nullable=True)
    revision_metadata = Column(LargeBinary(), nullable=True)
    crypt_hash = Column(String(250), nullable=True)
    file_size_crypt = Column(Integer(), nullable=True)

    def assert_valid(self):
        if self.vault_id is None:
            raise InvalidRevision("Invalid vault_id: {0}".format(self.vault_id))
        if self.user_id is None:
            raise InvalidRevision("Invalid user_id: {0}".format(self.user_id))
        if self.user_fingerprint is None:
            raise InvalidRevision(
                "Invalid user_fingerprint: {0}".format(self.user_fingerprint)
            )

        if self.operation == RevisionOp.CreateVault:
            assert self.parent_id is None
            if not isinstance(self.public_key, bytes):
                raise InvalidRevision("Wrong type for public_key")
        elif self.operation == RevisionOp.Upload:
            assert self.parent_id is not None
        elif self.operation == RevisionOp.SetMetadata:
            assert self.parent_id is not None
        elif self.operation == RevisionOp.DeleteFile:
            assert self.parent_id is not None
            assert self.file_hash
        else:
            raise NotImplementedError(self.operation)

    def _message(self):
        if self.operation == RevisionOp.CreateVault:
            message = str(self.operation).encode() + b"|"
            message += str(self.nonce).encode() + b"|"
            message += self.public_key
        elif self.operation == RevisionOp.Upload:
            message = str(self.operation).encode() + b"|"
            message += str(self.parent_id).encode() + b"|"
            message += str(self.file_hash).encode() + b"|"
            message += str(self.crypt_hash).encode() + b"|"
            message += str(self.file_size_crypt).encode() + b"|"
            message += self.revision_metadata
        elif self.operation == RevisionOp.SetMetadata:
            message = str(self.operation).encode() + b"|"
            message += str(self.parent_id).encode() + b"|"
            message += self.revision_metadata
        elif self.operation == RevisionOp.DeleteFile:
            message = str(self.operation).encode() + b"|"
            message += str(self.parent_id).encode() + b"|"
            message += str(self.file_hash).encode()
        else:
            raise NotImplementedError(self.operation)
        return message

    def sign(self, identity: Identity):
        self.assert_valid()
        self.signature = identity.sign(self._message())

    def verify(self, identity: Identity):
        """Verify the signature of this revision"""
        self.assert_valid()
        if self.signature is None:
            raise InvalidRevision("Revision is not signed")
        if not identity.verify(self._message(), self.signature):
            raise InvalidRevision(
                "Signature verifaction failed with key {0}".format(
                    identity.get_fingerprint()
                )
            )
