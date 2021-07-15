# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from flask import current_app, make_response, redirect, request, session, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from werkzeug.urls import url_parse

from flask_multipass.auth import AuthProvider
from flask_multipass.data import AuthInfo, IdentityInfo
from flask_multipass.exceptions import AuthenticationFailed, IdentityRetrievalFailed, MultipassException
from flask_multipass.identity import IdentityProvider
from flask_multipass.util import login_view


class SAMLAuthProvider(AuthProvider):
    """Provides authentication using SAML.

    The type name to instantiate this provider is *saml*.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.strip_prefix = self.settings.setdefault('strip_prefix', 'http://schemas.xmlsoap.org/claims/')
        self.saml_acs_uri = self.settings.setdefault('saml_acs_uri', f'/multipass/saml/{self.name}/acs')
        self.saml_sls_uri = self.settings.setdefault('saml_sls_uri', f'/multipass/saml/{self.name}/sls')
        self.saml_metadata_uri = self.settings.setdefault('saml_metadata_uri', f'/multipass/saml/{self.name}/metadata')
        self.saml_acs_endpoint = f'_flaskmultipass_saml_acs_{self.name}'
        self.saml_sls_endpoint = f'_flaskmultipass_saml_sls_{self.name}'
        self.saml_metadata_endpoint = f'_flaskmultipass_saml_metadata_{self.name}'
        current_app.add_url_rule(self.saml_acs_uri, self.saml_acs_endpoint, self._saml_acs, methods=('GET', 'POST'))
        current_app.add_url_rule(self.saml_sls_uri, self.saml_sls_endpoint, self._saml_sls, methods=('GET', 'POST'))
        current_app.add_url_rule(self.saml_metadata_uri, self.saml_metadata_endpoint, self._saml_metadata)

    @property
    def saml_config(self):
        return self.settings['saml_config']

    def _prepare_flask_request(self):
        url_data = url_parse(request.url)
        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'server_port': url_data.port,
            'script_name': request.path,
            'get_data': request.args.copy(),
            'post_data': request.form.copy(),
            # enable when using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
            'lowercase_urlencoding': self.settings.get('lowercase_urlencoding', False)
        }

    def _init_saml_auth(self):
        config = dict(self.saml_config)
        config.setdefault('strict', True)
        config.setdefault('debug', False)
        idp_config = config.setdefault('idp', {})
        if not idp_config:
            # dummy data so we can generate the SP metadata
            idp_config.update({
                'entityId': 'https://idp.example.com',
                'singleSignOnService': {
                    'url': 'https://idp.example.com/saml',
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                },
                'singleLogoutService': {
                    'url': 'https://idp.example.com/saml',
                    'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
                },
                'x509cert': ''
            })
        config['sp'].setdefault('NameIDFormat', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent')
        acs_config = config['sp'].setdefault('assertionConsumerService', {})
        acs_config.setdefault('binding', "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
        acs_config['url'] = url_for(self.saml_acs_endpoint, _external=True)
        slo_config = config['sp'].get('singleLogoutService')
        if slo_config is not None:
            slo_config.setdefault('binding', "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
            slo_config['url'] = url_for(self.saml_sls_endpoint, _external=True)
        req = self._prepare_flask_request()
        return OneLogin_Saml2_Auth(req, config)

    def _make_session_key(self, name):
        return f'_flaskmultipass_saml_{self.name}_{name}'

    def initiate_external_login(self):
        auth = self._init_saml_auth()
        return redirect(auth.login())

    def process_logout(self, return_url):
        auth = self._init_saml_auth()
        if auth.get_slo_url() is None:
            return None
        name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
        name_id = session.get(self._make_session_key('name_id'), None)
        name_id_format = session.get(self._make_session_key('name_id_format'), None)
        name_id_nq = session.get(self._make_session_key('name_id_nq'), None)
        name_id_spnq = session.get(self._make_session_key('name_id_spnq'), None)
        session_index = session.get(self._make_session_key('session_index'), None)
        return redirect(auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq,
                                    name_id_format=name_id_format, spnq=name_id_spnq,
                                    return_to=return_url))

    @login_view
    def _saml_acs(self):
        auth = self._init_saml_auth()
        session_key_request_id = self._make_session_key('request_id')
        session_key_name_id = self._make_session_key('name_id')
        session_key_name_id_format = self._make_session_key('name_id_format')
        session_key_name_id_nq = self._make_session_key('name_id_nq')
        session_key_name_id_spnq = self._make_session_key('name_id_spnq')
        session_key_session_index = self._make_session_key('session_index')
        request_id = session.get(session_key_request_id)
        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        if errors:
            error_reason = 'SAML login failed'
            if auth.get_settings().is_debug_active():
                error_reason += f' ({auth.get_last_error_reason()})'
            raise AuthenticationFailed(error_reason)
        session.pop(session_key_request_id, None)
        session[session_key_name_id] = saml_nameid = auth.get_nameid()
        session[session_key_name_id_format] = auth.get_nameid_format()
        session[session_key_name_id_nq] = saml_nameid_nq = auth.get_nameid_nq()
        session[session_key_name_id_spnq] = saml_nameid_spnq = auth.get_nameid_spnq()
        session[session_key_session_index] = auth.get_session_index()

        attributes = auth.get_attributes()
        if self.strip_prefix:
            attributes = {
                (k[len(self.strip_prefix):] if k.startswith(self.strip_prefix) else k): v
                for k, v in attributes.items()
            }
        # flatten single-element lists; otherwise linking e.g. to an LDAP identity
        # provider is not possible
        attributes = {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in attributes.items()}
        attributes['_saml_nameid'] = saml_nameid
        attributes['_saml_nameid_qualified'] = '@'.join(x for x in [saml_nameid, saml_nameid_nq, saml_nameid_spnq]
                                                        if x is not None)
        if auth.get_settings().is_debug_active():
            print(f'Login successful; received attributes: {attributes}')
        if not attributes:
            raise AuthenticationFailed('No valid data received', provider=self)
        return self.multipass.handle_auth_success(AuthInfo(self, **attributes))

    def _saml_sls(self):
        auth = self._init_saml_auth()
        session_key_logout_request_id = self._make_session_key('logout_request_id')
        request_id = session.get(session_key_logout_request_id)
        dscb = lambda: session.clear()  # noqa: E731
        url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
        errors = auth.get_errors()
        if errors:
            error_reason = 'SAML logout failed'
            if auth.get_settings().is_debug_active():
                error_reason += f' ({auth.get_last_error_reason()})'
            raise MultipassException(error_reason)
        if url is not None:
            return redirect(url)
        else:
            return redirect(auth.redirect_to(request.form.get('RelayState', '/')))

    def _saml_metadata(self):
        auth = self._init_saml_auth()
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if errors:
            return make_response(', '.join(errors), 500)
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
        return resp


class SAMLIdentityProvider(IdentityProvider):
    """Provides identity information using SAML.

    The type name to instantiate this provider is *saml*.
    """

    #: If the provider supports getting identity information based from
    #: an identifier
    supports_get = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.id_field = self.settings.setdefault('identifier_field', '_saml_nameid_qualified')

    def get_identity_from_auth(self, auth_info):
        identifier = auth_info.data.get(self.id_field)
        if isinstance(identifier, list):
            if len(identifier) != 1:
                raise IdentityRetrievalFailed('Identifier has multiple elements', provider=self)
            identifier = identifier[0]
        if not identifier:
            raise IdentityRetrievalFailed('Identifier missing in saml response', provider=self)
        return IdentityInfo(self, identifier=identifier, **auth_info.data)
