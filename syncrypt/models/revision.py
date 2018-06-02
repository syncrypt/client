from enum import Enum

from sqlalchemy import Binary, Column, DateTime, ForeignKey, Integer, LargeBinary, String

from syncrypt.exceptions import InvalidRevision

from .base import Base


class RevisionOp(Enum):
    CreateVault = 'OP_CREATE_VAULT'
    Upload = 'OP_UPLOAD'


class Revision(Base):
    __tablename__ = 'revision'

    id = Column(String(128), primary_key=True)
    parent_id = Column(String(128), ForeignKey('revision.id'), nullable=True)
    vault_id = Column(String(128))

    # These are the core fields that every transaction has to have.
    operation = Column(String(32))
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
            raise InvalidRevision('Invalid vault_id: {0}'.format(self.vault_id))
        if self.user_id is None:
            raise InvalidRevision('Invalid user_id: {0}'.format(self.user_id))
        if self.user_fingerprint is None:
            raise InvalidRevision('Invalid user_fingerprint: {0}'.format(self.user_fingerprint))

        if self.operation == RevisionOp.CreateVault:
            assert self.parent_id is None
            if not isinstance(self.public_key, bytes):
                raise InvalidRevision('Wrong type for public_key')

        elif self.operation == RevisionOp.Upload:
            assert self.parent_id is not None
        else:
            raise NotImplementedError()

    def sign(self, identity):
        self.assert_valid()
        if self.operation == RevisionOp.CreateVault:
            message = str(self.operation).encode() + b'|'
            message += str(self.nonce).encode() + b'|'
            message += self.public_key
            self.signature = identity.sign(message)
        elif self.operation == RevisionOp.Upload:
            message = str(self.operation).encode() + b'|'
            message += str(self.parent_id).encode() + b'|'
            message += str(self.file_hash).encode() + b'|'
            message += str(self.crypt_hash).encode() + b'|'
            message += str(self.file_size_crypt).encode() + b'|'
            message += self.revision_metadata
            self.signature = identity.sign(message)
        else:
            raise NotImplementedError

    def verify(self, identity):
        '''Verify the signature of this revision'''
        raise NotImplementedError
