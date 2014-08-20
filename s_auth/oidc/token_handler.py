from oauthlib.oauth2.rfc6749.tokens import BearerToken
import hashlib
import jot
import jot.codec
import time


_AT_HASH_ALGORITHMS = {
    'HS256': lambda d: hashlib.sha256(d).digest(),
}


class OIDCToken(BearerToken):
    def __init__(self, request_validator, signature_key=None,
            signature_alg='HS256', *args, **kwargs):
        BearerToken.__init__(self, request_validator, *args, **kwargs)
        self.signature_key = signature_key
        self.signature_alg = signature_alg

    def create_id_token(self, request, bearer_token):
        # NOTE If we're doing implicit, we need to encrypt the token for the
        # intended party.  We could associate encryption keys with each client
        # in the database and fetch the client objects from the
        # request_validator, then get their public keys.

        user = self.request_validator.get_user(request)
        # create token
        iat = int(time.time())
        exp = iat + 600
        id_token = jot.Token(claims={
            'iss': 'https://auth.ptero.gsc.wustl.edu',
            'sub': user.sub,
            'aud': request.client_id,
            'exp': exp,
            'iat': iat,
            'at_hash': self._at_hash(bearer_token['access_token']),
            'user_details': {
                'uid': user.user_id,
                'name': user.name,
                'roles': [r.name for r in user.roles],
            },
        })

        jws = id_token.sign_with(self.signature_key, alg=self.signature_alg)

        if (request.response_type == 'token id_token'
               or request.response_type == 'id_token token'):
            pass
            # encrypt token

        # serialize token
        return jws.compact_serialize()

    def create_token(self, request, refresh_token=False):
        token = super(OIDCToken, self).create_token(request, refresh_token)
        if 'openid' in self.request_validator.get_scopes(request):
            token['id_token'] = self.create_id_token(request, token)
        return token

    def _at_hash(self, access_token):
        hasher = _AT_HASH_ALGORITHMS[self.signature_alg]
        digest = hasher(access_token)
        l = len(digest) / 2
        return jot.codec.base64url_encode(digest[:l])
