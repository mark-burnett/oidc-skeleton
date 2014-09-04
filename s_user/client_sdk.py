from oauthlib.oauth2 import MobileApplicationClient
from .clients import OIDCMobileApplicationClient
from s_common.auth import auth_url
import os
import requests


class ClientSDK(object):
    def __init__(self, api_key):
        self.api_key = api_key
        self.token = None

    def get_forwarded_resource(self, name):
        url = self._client_url('forwarded-resource', name)
        response = requests.get(url)

        if response.status_code == 401:
            second_response = requests.post(response.headers['Location'],
                    headers={'Authorization': 'API Key ' + self.api_key})

            if second_response.status_code == 200:
                return second_response.json()

    @property
    def headers_for_direct_resource(self):
        headers = {}
        if self.token:
            headers['Identity'] = self.token['id_token']
            headers['Authorization'] = 'Bearer %s' % self.token['access_token']
        return headers

    def get_direct_resource(self, name):
        url = self._client_url('direct-resource', name)
        client = OIDCMobileApplicationClient(client_id='user:ci')

        response = requests.get(url, headers=self.headers_for_direct_resource)
        if response.status_code == 401:
            self.token = self._implicit_authenticate(client, url)

            second_response = requests.get(url, headers=self.headers_for_direct_resource)

            if second_response.status_code == 200:
                return second_response.json()

        else:
            if response.status_code == 200:
                return response.json()

    def _client_url(self, *path):
        return os.path.join(os.environ['CLIENT_URL'], *path)

    def _implicit_authenticate(self, client, url):
        scope = ['client', 'openid']
        state = None
        authorization_url = client.prepare_request_uri(auth_url('authorize'),
                redirect_uri=url, scope=scope, state=state)

        authorization_response = requests.post(authorization_url,
                headers={'Authorization': 'API Key ' + self.api_key},
                allow_redirects=False)

        if not authorization_response.status_code == 302:
            raise RuntimeError('Failed to authenticate with API key')

        return client.parse_request_uri_response(
                authorization_response.headers['Location'],
                scope=scope, state=state)
