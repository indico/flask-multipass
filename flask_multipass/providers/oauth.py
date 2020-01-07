# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from authlib.common.errors import AuthlibBaseError
from authlib.integrations.flask_client import RemoteApp
from flask import current_app, url_for, request

from flask_multipass.auth import AuthProvider
from flask_multipass.data import AuthInfo, IdentityInfo
from flask_multipass.exceptions import AuthenticationFailed, IdentityRetrievalFailed
from flask_multipass.identity import IdentityProvider
from flask_multipass.util import login_view


class OAuthAuthProvider(AuthProvider):
    """Provides authentication using OAuth

    The type name to instantiate this provider is *oauth*.
    """

    def __init__(self, *args, **kwargs):
        super(OAuthAuthProvider, self).__init__(*args, **kwargs)
        self.settings.setdefault('callback_uri', '/oauth/{}'.format(self.name))
        oauth_settings = self.settings.setdefault('oauth', {})
        self.oauth_app = RemoteApp(self.name + '_flaskmultipass', **oauth_settings)
        self.authorized_endpoint = '_flaskmultipass_oauth_' + self.name
        current_app.add_url_rule(self.settings['callback_uri'], self.authorized_endpoint,
                                 self._authorize_callback, methods=('GET', 'POST'))

    def _get_redirect_uri(self):
        return url_for(self.authorized_endpoint, _external=True)

    def initiate_external_login(self):
        return self.oauth_app.authorize_redirect(self._get_redirect_uri())

    @login_view
    def _authorize_callback(self):
        error = request.args.get('error')
        if error:
            raise AuthenticationFailed(error, provider=self)
        try:
            token = self.oauth_app.authorize_access_token()
            return self.multipass.handle_auth_success(AuthInfo(self, token=token))
        except AuthlibBaseError as exc:
            raise AuthenticationFailed(str(exc), provider=self)


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
        oauth_settings = self.settings.setdefault('oauth', {})
        self.settings.setdefault('identifier_field', None)
        self.oauth_app = RemoteApp(self.name + '_flaskmultipass', **oauth_settings)

    def _get_identity(self, token):
        resp = self.oauth_app.request(self.settings['method'], self.settings['endpoint'], token=token)
        if resp.status_code not in self.settings['valid_statuses']:
            raise IdentityRetrievalFailed('Could not retrieve identity data', provider=self)
        elif resp.status_code == 404:
            return None
        data = resp.json()
        identifier = data[self.settings['identifier_field']]
        multipass_data = {'oauth_token': token}
        return IdentityInfo(self, identifier, multipass_data, **data)

    def get_identity_from_auth(self, auth_info):
        return self._get_identity(auth_info.data['token'])

    def refresh_identity(self, identifier, multipass_data):
        return self._get_identity(multipass_data['oauth_token'])


class OAuthInvalidSessionState(AuthenticationFailed):
    """Invalid CSRF token during OAuth.

    This usually happens when people start the OAuth process and then
    close their browser or just wait a long time before finishing it.
    """
