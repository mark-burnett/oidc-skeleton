from oauthlib.oauth2 import MobileApplicationClient
from requests_oauthlib import OAuth2Session
import os
import requests


class ClientSDK(object):
    def __init__(self, api_key):
        self.api_key = api_key
        self.oauth_session = OAuth2Session(
                client=MobileApplicationClient(client_id='user:ci'))

        self.token = None

    def get_forwarded_resource(self, name):
        url = self._client_url('forwarded-resource', name)
        response = requests.get(url)

        if response.status_code == 401:
            second_response = requests.post(response.headers['Location'],
                    headers={'Authorization': 'API Key ' + self.api_key})

            if second_response.status_code == 200:
                return second_response.json()

    def get_direct_resource(self, name):
        headers = {}
        if self.token:
            headers['Identity'] = self.token['id_token']

        url = self._client_url('direct-resource', name)

        response = self.oauth_session.get(url, headers=headers)
        if response.status_code == 401:
            self.token = self._implicit_authenticate(response)

            second_response = self.oauth_session.get(url, headers={'Identity':
                self.token['id_token']})

            if second_response.status_code == 200:
                return second_response.json()

        else:
            if response.status_code == 200:
                return response.json()

    def _client_url(self, *path):
        return os.path.join(os.environ['CLIENT_URL'], *path)

    def _implicit_authenticate(self, response):
        authorization_response = requests.post(response.headers['Location'],
                headers={'Authorization': 'API Key ' + self.api_key},
                allow_redirects=False)
        if not authorization_response.status_code == 302:
            raise RuntimeError('Failed to authenticate with API key')

        return self.oauth_session.token_from_fragment(
                authorization_response.headers['Location'])
