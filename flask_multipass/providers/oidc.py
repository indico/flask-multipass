# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2019 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import requests
from authlib.common.errors import AuthlibBaseError
from authlib.common.security import generate_token
from authlib.integrations.flask_client import RemoteApp
from authlib.jose import jwk, jwt
from authlib.oidc.core import CodeIDToken, ImplicitIDToken, UserInfo
from flask import current_app, redirect, request, session, url_for
from werkzeug.urls import url_encode, url_join

from flask_multipass.auth import AuthProvider
from flask_multipass.data import AuthInfo, IdentityInfo
from flask_multipass.exceptions import AuthenticationFailed, IdentityRetrievalFailed
from flask_multipass.identity import IdentityProvider
from flask_multipass.util import login_view


# jwt/oidc-specific fields that are not relevant to applications
INTERNAL_FIELDS = ('nonce', 'session_state', 'acr', 'jti', 'exp', 'azp', 'iss', 'iat', 'auth_time', 'typ', 'nbf', 'aud')


class OIDCAuthProvider(AuthProvider):
    """Provides authentication using OpenID Connect

    The type name to instantiate this provider is *oidc*.
    """

    def __init__(self, *args, **kwargs):
        super(OIDCAuthProvider, self).__init__(*args, **kwargs)
        self.settings.setdefault('callback_uri', '/oidc/{}'.format(self.name))
        oidc_settings = self.settings.setdefault('oidc', {
            'client_id': None,
            'client_secret': None,
            'authorize_url': None,
            'access_token_url': None,
            'issuer': None
        })
        oidc_settings.setdefault('logout_url', None)
        oidc_settings.setdefault('jwks_url', None)
        oidc_settings.setdefault('jwks', None)  # used as a cache, but could also be pre-populated
        client_kwargs = oidc_settings.setdefault('client_kwargs', {})
        scopes = set(client_kwargs.get('scope', '').split()) | {'openid'}
        client_kwargs['scope'] = ' '.join(sorted(scopes))
        self.oauth_app = RemoteApp(self.name + '_flaskmultipass',
                                   client_id=oidc_settings['client_id'],
                                   client_secret=oidc_settings['client_secret'],
                                   authorize_url=oidc_settings['authorize_url'],
                                   access_token_url=oidc_settings['access_token_url'],
                                   client_kwargs=oidc_settings['client_kwargs'])
        self.authorized_endpoint = '_flaskmultipass_oidc_' + self.name
        current_app.add_url_rule(self.settings['callback_uri'], self.authorized_endpoint,
                                 self._authorize_callback, methods=('GET', 'POST'))

    @property
    def oidc_settings(self):
        return self.settings['oidc']

    def _get_redirect_uri(self):
        return url_for(self.authorized_endpoint, _external=True)

    @property
    def _session_key(self):
        return '_multipass_oidc_nonce_' + self.name

    def initiate_external_login(self):
        session[self._session_key] = nonce = generate_token(20)
        return self.oauth_app.authorize_redirect(self._get_redirect_uri(), nonce=nonce)

    def process_logout(self, return_url):
        logout_url = self.oidc_settings['logout_url']
        if logout_url:
            return_url = url_join(request.url_root, return_url)
            query = url_encode({'post_logout_redirect_uri': return_url})
            return redirect(logout_url + '?' + query)

    def _load_jwk(self, header, payload):
        if self.oidc_settings['jwks'] is not None:
            try:
                return jwk.loads(self.oidc_settings['jwks'], header.get('kid'))
            except ValueError:
                pass
        # no jwks cached or couldn't use them
        if not self.oidc_settings['jwks_url']:
            raise ValueError('No JWKS available')
        self.oidc_settings['jwks'] = jwk_set = requests.get(self.oidc_settings['jwks_url']).json()
        return jwk.loads(jwk_set, header.get('kid'))

    # based on https://github.com/authlib/loginpass/blob/master/loginpass/_core.py (BSD)
    def _parse_id_token(self, token_data, nonce):
        id_token = token_data['id_token']
        claims_params = {'nonce': nonce, 'client_id': self.oidc_settings['client_id']}
        if 'access_token' in token_data:
            claims_params['access_token'] = token_data['access_token']
            claims_cls = CodeIDToken
        else:
            claims_cls = ImplicitIDToken
        # XXX: should we allow extra claims to be specified in the settings?
        claims_options = {'iss': {'values': [self.oidc_settings['issuer']]}}
        claims = jwt.decode(
            id_token,
            key=self._load_jwk,
            claims_cls=claims_cls,
            claims_options=claims_options,
            claims_params=claims_params,
        )
        claims.validate(leeway=120)
        info = UserInfo(claims)
        for key in INTERNAL_FIELDS:
            info.pop(key, None)
        return info

    @login_view
    def _authorize_callback(self):
        # if authorization failed abort early
        error = request.args.get('error')
        if error:
            raise AuthenticationFailed(error, provider=self)
        # try to get a token containing a valid oidc id token
        try:
            oauth_token_data = self.oauth_app.authorize_access_token()
            id_token = self._parse_id_token(oauth_token_data, session.pop(self._session_key))
            return self.multipass.handle_auth_success(AuthInfo(self, **id_token))
        except AuthlibBaseError as exc:
            raise AuthenticationFailed(str(exc), provider=self)


class OIDCIdentityProvider(IdentityProvider):
    """Provides identity information using OIDC.

    This provides access to all data included in the ID token
    The type name to instantiate this provider is *oidc*.
    """

    #: If the provider supports refreshing identity information
    supports_refresh = False
    #: If the provider supports getting identity information based from
    #: an identifier
    supports_get = False

    def __init__(self, *args, **kwargs):
        super(OIDCIdentityProvider, self).__init__(*args, **kwargs)
        self.id_field = self.settings.setdefault('identifier_field', 'sub').lower()

    def get_identity_from_auth(self, auth_info):
        identifier = auth_info.data.get(self.id_field)
        if not identifier:
            raise IdentityRetrievalFailed('Identifier ({}) missing in oidc response'.format(self.id_field),
                                          provider=self)
        return IdentityInfo(self, identifier=identifier, **auth_info.data)
