# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import flask_oauthlib.client
from flask import current_app, url_for

from flask_multiauth.auth import AuthProvider
from flask_multiauth.data import AuthInfo
from flask_multiauth.util import classproperty


_oauth_settings = ('base_url', 'request_token_url', 'access_token_url', 'authorize_url',
                   'consumer_key', 'consumer_secret',
                   'request_token_params', 'request_token_method', 'access_token_params', 'access_token_method')


class OAuth(flask_oauthlib.client.OAuth):
    """A Flask-OAuthlib client that lives in its own namespace.

    This avoids collisions in case the main application also uses
    Flask-OAuthlib for something else.
    """

    state_key = flask_oauthlib.client.OAuth.state_key + '.flaskmultiauth'

    @classproperty
    @classmethod
    def instance(cls):
        """Gets the OAuth instance from the current app.

        If necessary, a new instance of this extension is registered
        on the app.
        """
        oauth = current_app.extensions.get(cls.state_key)
        if oauth is None:
            oauth = cls(current_app)
            oauth.init_app(current_app)
        return oauth


class OAuthAuthProvider(AuthProvider):
    """Provides authentication using OAuth2"""

    #: The type to use in the auth provider config.
    type = 'oauth'

    def __init__(self, *args, **kwargs):
        super(OAuthAuthProvider, self).__init__(*args, **kwargs)
        self.settings.setdefault('callback_uri', '/oauth/{}'.format(self.name))
        self.settings.setdefault('oauth', {})
        self.settings.setdefault('token_field', 'access_token')
        self.oauth_app = OAuth.instance.remote_app(self.name + '_flaskmultiauth', register=False,
                                                   **self.settings['oauth'])
        self.authorized_endpoint = '_flaskmultiauth_oauth_' + self.name
        current_app.add_url_rule(self.settings['callback_uri'], self.authorized_endpoint,
                                 self._authorize_callback, methods=('GET', 'POST'))

    def initiate_external_login(self):
        redirect_uri = url_for(self.authorized_endpoint, _external=True)
        return self.oauth_app.authorize(callback=redirect_uri)

    def _make_auth_info(self, resp):
        return AuthInfo(self, token=resp[self.settings['token_field']])

    def _authorize_callback(self):
        resp = self.oauth_app.authorized_response()
        self.multiauth.handle_auth_info(self._make_auth_info(resp))
        return self.multiauth.redirect_success()
