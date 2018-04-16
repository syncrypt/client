from sqlalchemy import Column, Integer, String
from .base import Base


class Revision(Base):
    __tablename__ = 'revision'

    id = Column(Integer(), primary_key=True)
    file_hash = Column(String(50))
    user_email = Column(String(50))
