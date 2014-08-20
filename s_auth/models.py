from sqlalchemy import Boolean, Column, ForeignKey, Integer, Table, Text
from sqlalchemy.orm import column_property, relationship
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy
import uuid


Base = declarative_base()


def uuid_generator():
    return str(uuid.uuid4())


def double_uuid_generator():
    return uuid_generator() + uuid_generator()


class Client(Base):
    __tablename__ = 'client'

    client_pk = Column(Integer, primary_key=True)
    client_id = Column(Text, index=True, unique=True, nullable=False,
            default=lambda: double_uuid_generator() + ':ci')
    client_secret = Column(Text,
            default=lambda: double_uuid_generator() + ':cs')
    requires_validation = Column(Boolean, default=True)

    name = Column(Text)
    grant_type = Column(Text, nullable=False)
    response_type = Column(Text, nullable=False)

    _scope = Column(Text)

    @property
    def scopes(self):
        return self._scope.split(' ')

    @scopes.setter
    def scopes(self, value):
        self._scope = ' '.join(value)


user_roles_table = Table('user_role', Base.metadata,
        Column('user_id', Integer, ForeignKey('user.user_id')),
        Column('role_id', Integer, ForeignKey('role.role_id')))


class User(Base):
    __tablename__ = 'user'

    user_id = Column(Integer, primary_key=True)
    name = Column(Text, index=True, nullable=False, unique=True)
    sub = Column(Text, nullable=False, unique=True, default=lambda:
            uuid.uuid4().hex)

    roles = relationship('Role', secondary=user_roles_table, backref='users')


class Role(Base):
    __tablename__ = 'role'

    role_id = Column(Integer, primary_key=True)
    name = Column(Text, index=True, nullable=False, unique=True)


class Key(Base):
    __tablename__ = 'api_key'

    key_id = Column(Integer, primary_key=True)
    key = Column(Text, index=True, unique=True, nullable=False,
            default=lambda: double_uuid_generator() + ':k')
    user_id = Column(Integer, ForeignKey('user.user_id'), nullable=False)

    user = relationship(User)


class AuthorizationCode(Base):
    __tablename__ = 'authorization_code'

    authorization_code_id = Column(Integer, primary_key=True)
    code = Column(Text, index=True, unique=True, nullable=False,
            default=lambda: double_uuid_generator() + ':g')
    api_key_id = Column(Integer, ForeignKey('api_key.key_id'), nullable=False)
    client_pk = Column(Integer, ForeignKey('client.client_pk'), nullable=False)
    _scope = Column(Text, nullable=False, default='')

    api_key = relationship(Key)
    client = relationship(Client)

    @property
    def scope(self):
        return self._scope.split(' ')

    @scope.setter
    def scope(self, value):
        self._scope = ' '.join(value)


class RefreshToken(Base):
    __tablename__ = 'refresh_token'

    refresh_token_id = Column(Integer, primary_key=True)
    authorization_code_id = Column(Integer,
            ForeignKey('authorization_code.authorization_code_id'),
            nullable=False)

    token = Column(Text, index=True, unique=True, nullable=False,
            default=lambda: double_uuid_generator() + ':rt')

    authorization_code = relationship(AuthorizationCode)


class AccessToken(Base):
    __tablename__ = 'access_token'

    access_token_id = Column(Integer, primary_key=True)
    token = Column(Text, index=True, unique=True, nullable=False,
            default=lambda: double_uuid_generator() + ':at')
    refresh_token_id = Column(Integer,
            ForeignKey('refresh_token.refresh_token_id'))

    refresh_token = relationship(RefreshToken)

    @property
    def scopes(self):
        return self.refresh_token.authorization_code.scope

    @property
    def user(self):
        return self.refresh_token.authorization_code.api_key.user

    @property
    def as_dict(self):
        return {
            'access_token': self.token,
            'refresh_token': self.refresh_token.token,
            'expires_in': '300',
            'scope': self.refresh_token.authorization_code._scope,
        }
