from flask import request
from .auth import auth_url
import jot
import jot.codec
import os
import hashlib


def validate_request_roles(scopes, allowed_roles, signed_id_token):
    if signed_id_token.verify_with(os.environ['OIDC_SIGNATURE_KEY']):
        id_token = signed_id_token.payload

        if not _valid_id_token(id_token):
            return False

        if not _valid_bearer_token(id_token):
            return False

        if not _valid_scopes(id_token, scopes):
            return False

        if not _valid_roles(id_token, allowed_roles):
            return False

        return True

    else:
        return False



def _valid_id_token(id_token):
    # XXX Check token expiration, audience, etc.
    return True

def _valid_bearer_token(id_token):
    bearer_token = _get_bearer_token()
    return True


def _valid_scopes(id_token, scopes):
    return True


def _valid_roles(id_token, allowed_roles):
    user_roles = set(id_token.claims['user_details']['roles'])
    allowed_roles = set(allowed_roles)
    if user_roles.intersection(allowed_roles):
        return True

    else:
        return False


def _get_bearer_token():
    return request.headers['Authorization'][8:]
