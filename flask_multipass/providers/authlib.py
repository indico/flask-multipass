# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the MIT License.

import logging
from urllib.parse import urlencode, urljoin

from authlib.common.errors import AuthlibBaseError
from authlib.integrations.flask_client import FlaskIntegration, OAuth
from flask import current_app, redirect, request, session, url_for
from requests.exceptions import HTTPError, RequestException, Timeout

from flask_multipass.auth import AuthProvider
from flask_multipass.data import AuthInfo, IdentityInfo
from flask_multipass.exceptions import AuthenticationFailed, IdentityRetrievalFailed, MultipassException
from flask_multipass.identity import IdentityProvider
from flask_multipass.util import login_view

# jwt/oidc-specific fields that are not relevant to applications
INTERNAL_FIELDS = ('nonce', 'session_state', 'acr', 'jti', 'exp', 'azp', 'iss', 'iat', 'auth_time', 'typ', 'nbf', 'aud')

_notset = object()


class _MultipassFlaskIntegration(FlaskIntegration):
    @staticmethod
    def load_config(oauth, name, params):
        # we do not support loading anything directly from the flask config
        return {}


class _MultipassOAuth(OAuth):
    framework_integration_cls = _MultipassFlaskIntegration

    def init_app(self, app, cache=None, fetch_token=None, update_token=None):
        # we do not use any of the flask extension functionality nor the registry
        # and do not want to prevent the main application from using it
        pass


_authlib_oauth = _MultipassOAuth('dummy')


class AuthlibAuthProvider(AuthProvider):
    """Provide authentication using Authlib (OAuth/OIDC).

    The type name to instantiate this provider is ``authlib``.

    The following settings are supported:

    - ``callback_uri``:  the relative uri used after a successful oauth login.
                         defaults to ``/multipass/authlib/<name>``, but you can
                         change it e.g. if your oauth/oidc infrastructure requires
                         a specific callback uri and you do not want to rely on the
                         default one.
    - ``include_token``: when set to ``True``, the AuthInfo passed to the
                         identity provider includes the ``token`` containing
                         the raw token data received from oauth. this is useful
                         when connecting this auth provider to a custom identity
                         provider that needs to do more than just calling the
                         userinfo endpoint.
                         when set to `'only'`, the AuthInfo will *only* contain
                         the token, and no other data will be retrieved from the
                         id token or userinfo endpoint.
    - ``use_id_token``:  specify whether to use the OIDC id token instead of
                         calling the userinfo endpoint. if unspecified or None,
                         it will default to true when the ``openid`` scope is
                         enabled (which indicates that OIDC is being used)
    - ``authlib_args``:  a dict of params forwarded to authlib. see the arguments
                         of ``register()`` in the
                         `authlib docs <https://docs.authlib.org/en/latest/client/frameworks.html>`_
                         for details.
    - ``logout_uri``:    a custom URL to redirect to after logging out; can be set to
                         ``None`` to avoid using the URL from the OIDC metadata
    - ``logout_args``:   the special argument types to include in the query string of
                         the logout uri. defaults to
                         ``{'client_id', 'id_token_hint', 'post_logout_redirect_uri'}``
    - ``request_timeout``: the timeout in seconds for fetching the oauth token and
                           requesting data from the userinfo endpoint (10 by default,
                           set to None to disable)
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        callback_uri = self.settings.get('callback_uri', f'/multipass/authlib/{self.name}')
        self.authlib_client = _authlib_oauth.register(self.name, **self.authlib_settings)
        self.include_token = self.settings.get('include_token', False)
        self.request_timeout = self.settings.get('request_timeout')
        self.use_id_token = self.settings.get('use_id_token')
        self.logout_uri = self.settings.get('logout_uri', self.authlib_settings.get('logout_uri', _notset))
        self.logout_args = self.settings.get('logout_args', {'client_id', 'id_token_hint', 'post_logout_redirect_uri'})
        if self.use_id_token is None:
            # default to using the id token when using the openid scope (oidc)
            client_kwargs = self.authlib_settings.get('client_kwargs', {})
            scopes = client_kwargs.get('scope', '').split()
            self.use_id_token = 'openid' in scopes
        self.authorized_endpoint = '_flaskmultipass_authlib_' + self.name
        current_app.add_url_rule(callback_uri, self.authorized_endpoint, self._authorize_callback,
                                 methods=('GET', 'POST'))

    @property
    def authlib_settings(self):
        return self.settings['authlib_args']

    @property
    def _id_token_key(self):
        return f'_multipass_authlib_id_token:{self.name}'

    def _get_redirect_uri(self):
        return url_for(self.authorized_endpoint, _external=True)

    def initiate_external_login(self):
        try:
            return self.authlib_client.authorize_redirect(self._get_redirect_uri())
        except RequestException:
            logging.getLogger('multipass.authlib').exception('Initiating Authlib login failed')
            multipass_exc = AuthenticationFailed('Logging in is currently not possible due to an error', provider=self)
            return self.multipass.handle_auth_error(multipass_exc, True)

    def process_logout(self, return_url):
        logout_uri = (
            self.authlib_client.load_server_metadata().get('end_session_endpoint')
            if self.logout_uri is _notset
            else self.logout_uri
        )
        if not logout_uri:
            return
        return_url = urljoin(request.url_root, return_url)
        client_id = self.authlib_settings['client_id']
        query_args = {}
        if 'client_id' in self.logout_args:
            query_args['client_id'] = client_id
        if 'post_logout_redirect_uri' in self.logout_args:
            query_args['post_logout_redirect_uri'] = return_url
        if (id_token := session.pop(self._id_token_key, None)) and 'id_token_hint' in self.logout_args:
            query_args['id_token_hint'] = id_token
        query = urlencode(query_args)
        return redirect((logout_uri + '?' + query) if query else logout_uri)

    @login_view
    def _authorize_callback(self):
        # if authorization failed abort early
        error = request.args.get('error')
        if error:
            raise AuthenticationFailed(error, provider=self)
        try:
            try:
                token_data = self.authlib_client.authorize_access_token(timeout=self.request_timeout)
            except Timeout as exc:
                logging.getLogger('multipass.authlib').error('Getting token timed out')
                raise MultipassException('Token request timed out, please try again later') from exc
            except HTTPError as exc:
                try:
                    data = exc.response.json()
                except ValueError:
                    data = {'error': 'unknown', 'error_description': exc.response.text}
                error = data.get('error', 'unknown')
                desc = data.get('error_description', repr(data))
                logging.getLogger('multipass.authlib').error(f'Getting token failed: {error}: %s', desc)  # noqa: G004
                raise
            authinfo_token_data = {}
            if (id_token := token_data.get('id_token')) and 'id_token_hint' in self.logout_args:
                session[self._id_token_key] = id_token
            if self.include_token == 'only':  # noqa: S105
                return self.multipass.handle_auth_success(AuthInfo(self, token=token_data))
            elif self.include_token:
                authinfo_token_data['token'] = token_data

            if self.use_id_token:
                try:
                    # authlib 1.0+ parses the id_token automatically
                    id_token = dict(token_data['userinfo'])
                except KeyError:
                    # older authlib versions
                    id_token = self.authlib_client.parse_id_token(token_data)
                for key in INTERNAL_FIELDS:
                    id_token.pop(key, None)
                return self.multipass.handle_auth_success(AuthInfo(self, **dict(authinfo_token_data, **id_token)))
            else:
                user_info = self.authlib_client.userinfo(token=token_data)
                return self.multipass.handle_auth_success(AuthInfo(self, **dict(authinfo_token_data, **user_info)))
        except AuthlibBaseError as exc:
            raise AuthenticationFailed(str(exc), provider=self)


class AuthlibIdentityProvider(IdentityProvider):
    """Provides identity information using Authlib.

    This provides access to all data returned by userinfo endpoint or id token.
    The type name to instantiate this provider is ``authlib``.
    """

    #: If the provider supports refreshing identity information
    supports_refresh = False
    #: If the provider supports getting identity information based from
    #: an identifier
    supports_get = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id_field = self.settings.setdefault('identifier_field', 'sub').lower()

    def get_identity_from_auth(self, auth_info):
        identifier = auth_info.data.get(self.id_field)
        if not identifier:
            raise IdentityRetrievalFailed(f'Identifier ({self.id_field}) missing in authlib response',
                                          details=auth_info.data, provider=self)
        return IdentityInfo(self, identifier=identifier, **auth_info.data)
