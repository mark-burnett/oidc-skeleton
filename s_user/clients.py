from oauthlib.oauth2.rfc6749.clients import mobile_application


class OIDCMobileApplicationClient(mobile_application.MobileApplicationClient):
    def prepare_request_uri(self, uri, redirect_uri=None, scope=None,
            state=None, **kwargs):
        return mobile_application.prepare_grant_uri(uri, self.client_id,
                'id_token token', redirect_uri=redirect_uri, state=state,
                scope=scope, **kwargs)
