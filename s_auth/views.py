from . import backend
from . import models
from .oauth_validator import OAuthRequestValidator
from .oidc.server import OIDCServer
from .oidc.token_handler import OIDCToken
from flask import jsonify, request
from flask.views import MethodView
import flask
import logging
import os
import urllib


LOG = logging.getLogger(__file__)


# -- OAuth setup
session = backend.Session()
oauth_validator = OAuthRequestValidator(session)
token_handler = OIDCToken(oauth_validator,
        signature_key=os.environ['OIDC_SIGNATURE_KEY'])
oidc_server = OIDCServer(oauth_validator, token_handler)


class AuthorizeView(MethodView):
    def get(self):
        return '', 401, {'Location': request.url}

    _IMPLICIT_RESPONSE_TYPES = set(['token', 'token id_token', 'id_token token'])
    def post(self):
        response_type = request.args['response_type']
        if response_type in self._IMPLICIT_RESPONSE_TYPES:
            return self._implicit_flow()

        elif response_type == 'code':
            return self._code_grant_flow()

        else:
            pass

    def _implicit_flow(self):
        # XXX Need a better way to extract data (why doesn't c_a_r do this?)
        scopes, request_data = oidc_server.validate_authorization_request(
                uri=request.url, body=request.data, headers=request.headers)

        api_key = request.headers['Authorization'][8:]
        LOG.debug('API key: (%s)', api_key)

        headers, body, status_code = oidc_server.create_authorization_response(
                uri=request.url, headers=request.headers, scopes=scopes,
                credentials={'api_key': api_key})

        LOG.info('authorize c_a_r: (%s, %s, %s)', headers, body,
            status_code)

        return '', status_code, headers


    def _code_grant_flow(self):
        scopes, request_data = oidc_server.validate_authorization_request(
                uri=request.url, body=request.data, headers=request.headers)

        api_key = request.headers['Authorization'][8:]
        LOG.debug('API key: (%s)', api_key)

        headers, body, status_code = oidc_server.create_authorization_response(
                uri=request.url, headers=request.headers, scopes=scopes,
                credentials={'api_key': api_key})

        LOG.info('authorize c_a_r: (%s, %s, %s)', headers, body,
            status_code)

        return '', status_code, headers


class TokenView(MethodView):
    def post(self):
        regenerated_body = urllib.urlencode(request.form)

        headers, body, status_code = oidc_server.create_token_response(
                uri=request.url, headers=request.headers, body=regenerated_body)

        return body, status_code, headers


# -- Flask app
app = flask.Flask('Auth')
app.add_url_rule('/authorize', view_func=AuthorizeView.as_view('authorize'))
app.add_url_rule('/token', view_func=TokenView.as_view('token'))
