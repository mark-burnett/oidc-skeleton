from . import models
import os
import sqlalchemy


engine = sqlalchemy.create_engine(os.environ['AUTH_DB_URI'])
models.Base.metadata.create_all(engine)
Session = sqlalchemy.orm.sessionmaker(bind=engine)


def insert_data_from_file(filename):
    import yaml
    data = yaml.load(open(filename))

    s = Session()

    clients = {}
    for name, client_data in data.get('clients', {}).iteritems():
        scopes = client_data.pop('scopes', [])
        c = models.Client(name=name, **client_data)
        c.scopes = scopes
        clients[name] = c
        s.add(c)

    roles = {}
    for name in get_roles(data):
        r = models.Role(name=name)
        roles[name] = r
        s.add(r)

    users = {}
    for name, user_data in data.get('users', {}).iteritems():
        u = models.User(name=name)
        users[name] = u
        s.add(u)

        for key in user_data.get('api_keys', []):
            k = models.Key(key=key, user=u)
            s.add(k)

        for role_name in user_data.get('roles', []):
            u.roles.append(roles[role_name])

    s.commit()


def get_roles(data):
    roles = set()
    for user_name, user_data in data.get('users', {}).iteritems():
        roles.update(user_data.get('roles', []))
    return roles


def validate_api_key(api_key, scopes, request_data):
    return True
