# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from uuid import uuid4

import flask_oauthlib.client
from flask import current_app, url_for, session, request

from flask_multipass.auth import AuthProvider
from flask_multipass.data import AuthInfo, IdentityInfo
from flask_multipass.exceptions import AuthenticationFailed, IdentityRetrievalFailed
from flask_multipass.identity import IdentityProvider
from flask_multipass.util import classproperty, login_view


class OAuth(flask_oauthlib.client.OAuth):
    """A Flask-OAuthlib client that lives in its own namespace.

    This avoids collisions in case the main application also uses
    Flask-OAuthlib for something else.
    """

    state_key = flask_oauthlib.client.OAuth.state_key + '.flaskmultipass'

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
    """Provides authentication using OAuth

    The type name to instantiate this provider is *oauth*.
    """

    def __init__(self, *args, **kwargs):
        super(OAuthAuthProvider, self).__init__(*args, **kwargs)
        self.settings.setdefault('callback_uri', '/oauth/{}'.format(self.name))
        self.settings.setdefault('oauth', {})
        self.settings.setdefault('token_field', 'access_token')
        self.oauth_app = OAuth.instance.remote_app(self.name + '_flaskmultipass', register=False,
                                                   **self.settings['oauth'])
        self.authorized_endpoint = '_flaskmultipass_oauth_' + self.name
        current_app.add_url_rule(self.settings['callback_uri'], self.authorized_endpoint,
                                 self._authorize_callback, methods=('GET', 'POST'))

    def initiate_external_login(self):
        redirect_uri = url_for(self.authorized_endpoint, _external=True)
        session['_multipass_oauth_' + self.name] = token = str(uuid4())
        return self.oauth_app.authorize(callback=redirect_uri, state=token)

    def _make_auth_info(self, resp):
        return AuthInfo(self, token=resp[self.settings['token_field']])

    @login_view
    def _authorize_callback(self):
        token = session.pop('_multipass_oauth_' + self.name, None)
        if not token or token != request.args.get('state'):
            raise AuthenticationFailed('Invalid session state')
        resp = self.oauth_app.authorized_response() or {}
        if isinstance(resp, flask_oauthlib.client.OAuthException):
            error_details = {'msg': resp.message, 'type': resp.type, 'data': resp.data}
            raise AuthenticationFailed('OAuth error', details=error_details)
        elif self.settings['token_field'] not in resp:
            error = resp.get('error_description', resp.get('error', 'Received no oauth token'))
            raise AuthenticationFailed(error)
        return self.multipass.handle_auth_success(self._make_auth_info(resp))


class OAuthIdentityProvider(IdentityProvider):
    """Provides identity information using OAuth.

    The remote service needs to provide identity information as JSON.
    The type name to instantiate this provider is *oauth*.
    """

    #: If the provider supports refreshing identity information
    supports_refresh = True
    #: If the provider supports getting identity information based from
    #: an identifier
    supports_get = False

    def __init__(self, *args, **kwargs):
        super(OAuthIdentityProvider, self).__init__(*args, **kwargs)
        self.settings.setdefault('method', 'GET')
        self.settings.setdefault('valid_statuses', {200, 404})
        self.settings.setdefault('endpoint', None)
        self.settings.setdefault('oauth', {})
        self.settings.setdefault('identifier_field', None)
        self.oauth_app = OAuth.instance.remote_app(self.name + '_flaskmultipass', register=False,
                                                   **self.settings['oauth'])

    def _get_identity(self, token):
        resp = self.oauth_app.request(self.settings['endpoint'], method=self.settings['method'], token=(token, None))
        if resp.status not in self.settings['valid_statuses']:
            raise IdentityRetrievalFailed('Could not retrieve identity data')
        elif resp.status == 404:
            return None
        identifier = resp.data[self.settings['identifier_field']]
        multipass_data = {'oauth_token': token}
        return IdentityInfo(self, identifier, multipass_data, **resp.data)

    def get_identity_from_auth(self, auth_info):
        return self._get_identity(auth_info.data['token'])

    def refresh_identity(self, identifier, multipass_data):
        return self._get_identity(multipass_data['oauth_token'])
