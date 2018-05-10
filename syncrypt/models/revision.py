from sqlalchemy import Column, Integer, String, DateTime
from .base import Base


class Revision(Base):
    __tablename__ = 'revision'

    id = Column(String(128), primary_key=True)
    vault_id = Column(String(128))
    file_hash = Column(String(250))
    path = Column(String(255))
    user_email = Column(String(250))
    created_at = Column(DateTime())
    operation = Column(String(32))
