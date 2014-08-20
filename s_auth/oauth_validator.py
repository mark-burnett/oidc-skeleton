from . import models
from oauthlib.oauth2 import RequestValidator


class OAuthRequestValidator(RequestValidator):
    def __init__(self, session, keychain=None):
        self.session = session
        if keychain is not None:
            self.keychain = keychain

        else:
            self.keychain = {}

    def _get_client(self, client_id):
        return self.session.query(models.Client
                ).filter_by(client_id=client_id).first()

    def _get_key(self, request):
        return self.session.query(models.Key
                ).filter_by(key=request.headers['Authorization'][8:]).one()

    def get_user(self, request):
        if request.code:
            ac = self.session.query(models.AuthorizationCode
                    ).filter_by(code=request.code).one()
            return ac.api_key.user

        else:
            # XXX Is this used?
            key = self._get_key(request)
            return key.user

    def get_scopes(self, request):
        if request.scope:
            return request.scope.split(' ')

        elif request.code:
            ac = self.session.query(models.AuthorizationCode
                    ).filter_by(code=request.code).one()

            return ac.scope


    def validate_client_id(self, client_id, request):
        return self._get_client(client_id) is not None

    def validate_redirect_uri(self, client_id, redirect_uri, request):
        # XXX Needed
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        return True

    def validate_scopes(self, client_id, scopes, client, request):
        c = self._get_client(client_id)

        if scopes:
            requested_scopes = set(scopes)
        else:
            requested_scopes = set()
        allowed_scopes = set(c.scopes)

        result = requested_scopes.issubset(allowed_scopes)

        return result

    def get_default_scopes(self, client_id, request):
        return self._get_client(client_id).scopes

    def validate_response_type(self, client_id, response_type, client, request):
        c = self._get_client(client_id)
        return response_type == c.response_type

    def save_authorization_code(self, client_id, code, request):
        key = self._get_key(request)

        ac = models.AuthorizationCode(code=code['code'],
                api_key=key, client=self._get_client(client_id))
        ac.scope = request.scopes
        self.session.add(ac)
        self.session.commit()

    def client_authentication_required(self, request):
        c = self._get_client(request.client_id)
        return c.requires_validation

    def authenticate_client(self, request):
        c = self._get_client(request.client_id)
        if request.client_secret == c.client_secret:
            request.client = c
            return True

        else:
            return False

    def validate_grant_type(self, client_id, grant_type, client, request):
        return grant_type == client.grant_type

    def validate_code(self, client_id, code, client, request):
        return self.session.query(models.AuthorizationCode).filter_by(
                code=code, client=client).first()

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client):
        # XXX Should be picky, maybe each client registers a regex?
        return True

    def save_bearer_token(self, token, request):
        code = self.session.query(models.AuthorizationCode
                ).filter_by(code=request.code).first()

        if not code:
            # XXX Be sure to set this code as inactive
            client = self._get_client(request.client_id)
            code = models.AuthorizationCode(client=client,
                    api_key=self._get_key(request))
            code.scope = request.scopes
            self.session.add(code)

        r = models.RefreshToken(token=token.get('refresh_token'),
                authorization_code=code)
        a = models.AccessToken(token=token['access_token'], refresh_token=r)
        self.session.add(r)
        self.session.add(a)
        self.session.commit()

    def invalidate_authorization_code(self, client_id, code, request):
        # XXX Should flag the code as inactive/invalid
        pass


    def validate_bearer_token(self, token, scopes, request):
        # NOTE We might not need this here, since the auth server is never
        #      going to do this..
        # XXX Use extract id_token (from header?) to validate access token
        #     Need:
        #     - keychain of valid verification keys
        pass
