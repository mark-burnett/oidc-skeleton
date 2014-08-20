from . import backend
from . import models
from flask import jsonify, redirect, request
from flask.views import MethodView
from .oauthlib_clients import OIDCMobileApplicationClient
from requests_oauthlib import OAuth2Session
from s_common.auth import auth_url
from s_common.validate import validate_request_roles
import flask
import jot
import os
import requests


class DirectResourceView(MethodView):
    def get(self, name):
        if 'Authorization' in request.headers:
            s = backend.Session()

            resource = s.query(models.Resource).get(name)
            signed_id_token = jot.deserialize(str(request.headers['Identity']))
            if resource and validate_request_roles(scopes='client',
                    allowed_roles=resource.allowed_roles,
                    signed_id_token=signed_id_token):
                return jsonify(resource.as_dict), 200

            else:
                return '', 403

        else:
            oauth_session = OAuth2Session(redirect_uri=request.url,
                client=OIDCMobileApplicationClient(
                    client_id=os.environ['USER_CLIENT_ID']),
                scope=['client', 'openid'])
            authorization_url, state = oauth_session.authorization_url(
                    auth_url('authorize'))

            return redirect(authorization_url)


class ForwardedResourceView(MethodView):
    def get(self, name):
        if 'state' in request.args:
            oauth_session = OAuth2Session(os.environ['CLIENT_CLIENT_ID'],
                    state=request.args['state'])
            token = oauth_session.fetch_token(auth_url('token'),
                    client_secret=os.environ['CLIENT_CLIENT_SECRET'],
                    authorization_response=request.url)

            response = oauth_session.get(self.forward_url(name),
                    headers={'Identity': token['id_token']})
            return response.text, response.status_code

        else:
            oauth_session = OAuth2Session(os.environ['CLIENT_CLIENT_ID'],
                    redirect_uri=request.url, scope=['resource', 'openid'])
            authorization_url, state = oauth_session.authorization_url(
                    auth_url('authorize'))

            return redirect(authorization_url)

    def forward_url(self, name):
        return '%s/resource/%s' % (os.environ['RESOURCE_URL'], name)


app = flask.Flask('Client')
app.add_url_rule('/direct-resource/<string:name>',
        view_func=DirectResourceView.as_view('direct-resource'))
app.add_url_rule('/forwarded-resource/<string:name>',
        view_func=ForwardedResourceView.as_view('forwarded-resource'))
