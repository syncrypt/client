from sqlalchemy import Column, Integer, String, DateTime, Binary, LargeBinary, ForeignKey
from enum import Enum
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
    user_email = Column(String(250))
    created_at = Column(DateTime())
    signature = Column(Binary(512))

    # Additional fields for OP_CREATE_VAULT
    nonce = Column(Integer(), nullable=True)

    # Additional fields for OP_UPLOAD
    file_hash = Column(String(250), nullable=True)
    path = Column(String(255), nullable=True)
    revision_metadata = Column(LargeBinary(), nullable=True)
    crypt_hash = Column(String(250), nullable=True)
    file_size_crypt = Column(Integer(), nullable=True)

    def sign(self, identity):
        if self.operation == RevisionOp.CreateVault:
            assert self.parent_id is None
            self.signature = identity.sign(b'OP_CREATE_VAULT|' + str(self.nonce).encode())
        elif self.operation == RevisionOp.Upload:
            assert self.parent_id is not None
            message = b''
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
