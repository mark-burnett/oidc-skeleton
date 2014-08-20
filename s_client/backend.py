from . import models
import os
import sqlalchemy


engine = sqlalchemy.create_engine(os.environ['CLIENT_DB_URI'])
models.Base.metadata.create_all(engine)
Session = sqlalchemy.orm.sessionmaker(bind=engine)


def insert_data_from_file(filename):
    import yaml
    data = yaml.load(open(filename))

    s = Session()

    for name, resource_data in data.get('resources', {}).iteritems():
        allowed_roles = resource_data.pop('allowed_roles', [])
        r = models.Resource(name=name, **resource_data)
        r.allowed_roles = allowed_roles
        s.add(r)

    s.commit()
