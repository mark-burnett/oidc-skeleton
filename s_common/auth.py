import os
import urllib


def auth_url(path):
    return os.path.join(os.environ['AUTH_URL'], path)
