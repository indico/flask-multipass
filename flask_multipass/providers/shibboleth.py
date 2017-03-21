# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import urllib

from flask import request, current_app, url_for, redirect

from flask_multipass._compat import iteritems
from flask_multipass.auth import AuthProvider
from flask_multipass.data import AuthInfo, IdentityInfo
from flask_multipass.exceptions import MultipassException, AuthenticationFailed, IdentityRetrievalFailed
from flask_multipass.identity import IdentityProvider
from flask_multipass.util import login_view


class ShibbolethAuthProvider(AuthProvider):
    """Provides authentication using Shibboleth.

    This provider requires the application to run inside the Apache
    webserver with mod_shib.

    The type name to instantiate this provider is *shibboleth*.
    """

    def __init__(self, *args, **kwargs):
        super(ShibbolethAuthProvider, self).__init__(*args, **kwargs)
        self.settings.setdefault('attrs_prefix', 'ADFS_')
        if not self.settings.get('callback_uri'):
            raise MultipassException("`callback_uri` must be specified in the provider settings")
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
        attributes = {k: v for k, v in iteritems(request.environ) if k.startswith(self.settings['attrs_prefix'])}
        if not attributes:
            raise AuthenticationFailed("No valid data received")
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
        self.settings.setdefault('identifier_field', 'ADFS_LOGIN')

    def get_identity_from_auth(self, auth_info):
        identifier = auth_info.data.get(self.settings['identifier_field'])
        if not identifier:
            raise IdentityRetrievalFailed('Identifier missing in shibboleth response')
        return IdentityInfo(self, identifier=identifier, **auth_info.data)
