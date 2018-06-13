# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import urllib

from flask import request, current_app, url_for, redirect

from flask_multipass._compat import iteritems, PY2
from flask_multipass.auth import AuthProvider
from flask_multipass.data import AuthInfo, IdentityInfo
from flask_multipass.exceptions import MultipassException, AuthenticationFailed, IdentityRetrievalFailed
from flask_multipass.identity import IdentityProvider
from flask_multipass.util import login_view


def _to_unicode(s):
    return s.decode('utf-8') if PY2 and isinstance(s, str) else s


def _lower_keys(iter_):
    for k, v in iter_:
        yield k.lower(), v


class ShibbolethAuthProvider(AuthProvider):
    """Provides authentication using Shibboleth.

    This provider requires the application to run inside the Apache
    webserver with mod_shib.

    The type name to instantiate this provider is *shibboleth*.
    """

    def __init__(self, *args, **kwargs):
        super(ShibbolethAuthProvider, self).__init__(*args, **kwargs)
        # convert everything to lowercase (headers/WSGI vars are case-insensitive)
        self.attrs_prefix = self.settings.setdefault('attrs_prefix', 'ADFS_').lower()
        self.attrs = [attr.lower() for attr in self.settings.get('attrs', [])] or None
        if not self.settings.get('callback_uri'):
            raise MultipassException("`callback_uri` must be specified in the provider settings", provider=self)
        self.from_headers = self.settings.get('from_headers', False)
        self.shibboleth_endpoint = '_flaskmultipass_shibboleth_' + self.name
        current_app.add_url_rule(self.settings['callback_uri'], self.shibboleth_endpoint,
                                 self._shibboleth_callback, methods=('GET', 'POST'))

    def initiate_external_login(self):
        return redirect(url_for(self.shibboleth_endpoint))

    def process_logout(self, return_url):
        logout_uri = self.settings.get('logout_uri')
        if logout_uri:
            return redirect(logout_uri.format(return_url=urllib.quote(return_url)))

    @login_view
    def _shibboleth_callback(self):
        mapping = _lower_keys(iteritems(request.headers if self.from_headers else request.environ))
        # get all attrs in the 'attrs' list, if empty use 'attrs_prefix'
        if self.attrs is None:
            attributes = {k: _to_unicode(v) for k, v in mapping if k.startswith(self.attrs_prefix)}
        else:
            attributes = {k: _to_unicode(v) for k, v in mapping if k in self.attrs}

        if not attributes:
            raise AuthenticationFailed("No valid data received", provider=self)
        return self.multipass.handle_auth_success(AuthInfo(self, **attributes))


class ShibbolethIdentityProvider(IdentityProvider):
    """Provides identity information using Shibboleth

    This provider requires the application to run inside the Apache
    webserver with mod_shib.

    The type name to instantiate this provider is *shibboleth*.
    """

    #: If the provider supports getting identity information based from
    #: an identifier
    supports_get = False

    def __init__(self, *args, **kwargs):
        super(ShibbolethIdentityProvider, self).__init__(*args, **kwargs)
        # make headers/vars case-insensitive
        self.id_field = self.settings.setdefault('identifier_field', 'ADFS_LOGIN').lower()
        self.settings['mapping'] = {k: v.lower() for k, v in self.settings['mapping'].items()}

    def get_identity_from_auth(self, auth_info):
        identifier = auth_info.data.get(self.id_field)
        if not identifier:
            raise IdentityRetrievalFailed('Identifier missing in shibboleth response', provider=self)
        return IdentityInfo(self, identifier=identifier, **auth_info.data)
