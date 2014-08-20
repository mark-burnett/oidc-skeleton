import argparse
import logging
import os
from s_auth import backend
from s_auth.views import app
from urlparse import urlparse


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--data', help='YAML file to load into database')

    return parser.parse_args()


def port():
    url = urlparse(os.environ['AUTH_URL'])
    return url.port


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    args = parse_args()

    if args.data:
        backend.insert_data_from_file(args.data)

    app.run(port=port(), host='0.0.0.0')
