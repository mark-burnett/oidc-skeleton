from sqlalchemy import Boolean, Column, ForeignKey, Integer, Text
from sqlalchemy.orm import column_property, relationship
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy
import uuid


Base = declarative_base()


class Resource(Base):
    __tablename__ = 'resource'

    name = Column(Text, primary_key=True)
    data = Column(Text)

    _allowed_roles = Column(Text)

    @property
    def allowed_roles(self):
        return self._allowed_roles.split(' ')

    @allowed_roles.setter
    def allowed_roles(self, value):
        self._allowed_roles = ' '.join(value)

    @property
    def as_dict(self):
        return {
            'name': self.name,
            'data': self.data,
        }
