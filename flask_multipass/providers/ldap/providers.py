# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import absolute_import, unicode_literals

from warnings import warn

from ldap import INVALID_CREDENTIALS
from wtforms.fields import StringField, PasswordField
from wtforms.validators import DataRequired

from flask_multipass._compat import FlaskForm
from flask_multipass.auth import AuthProvider
from flask_multipass.data import AuthInfo, IdentityInfo
from flask_multipass.exceptions import NoSuchUser, InvalidCredentials, IdentityRetrievalFailed, GroupRetrievalFailed
from flask_multipass.group import Group
from flask_multipass.identity import IdentityProvider
from flask_multipass.util import convert_app_data

from flask_multipass.providers.ldap.globals import current_ldap
from flask_multipass.providers.ldap.operations import (build_user_search_filter, build_group_search_filter,
                                                       get_user_by_id, get_group_by_id, get_token_groups_from_user_dn,
                                                       search)
from flask_multipass.providers.ldap.util import ldap_context, to_unicode

try:
    import certifi
except ImportError:
    certifi = None


class LoginForm(FlaskForm):
    username = StringField('Username', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])


class LDAPProviderMixin(object):
    @property
    def ldap_settings(self):
        return self.settings['ldap']

    def set_defaults(self):
        self.ldap_settings.setdefault('timeout', 30)
        self.ldap_settings.setdefault('verify_cert', True)
        self.ldap_settings.setdefault('cert_file', certifi.where() if certifi else None)
        self.ldap_settings.setdefault('starttls', False)
        self.ldap_settings.setdefault('page_size', 1000)
        self.ldap_settings.setdefault('uid', 'uid')
        self.ldap_settings.setdefault('user_filter', '(objectClass=person)')
        if not self.ldap_settings['cert_file'] and self.ldap_settings['verify_cert']:
            warn("You should install certifi or provide a certificate file in order to verify the LDAP certificate.")
        # Convert LDAP settings to text in case someone gave us bytes
        self.settings['ldap'] = to_unicode(self.settings['ldap'])


class LDAPAuthProvider(LDAPProviderMixin, AuthProvider):
    """Provides authentication using LDAP

    The type name to instantiate this provider is *ldap*.
    """
    login_form = LoginForm

    def __init__(self, *args, **kwargs):
        super(LDAPAuthProvider, self).__init__(*args, **kwargs)
        self.set_defaults()

    def process_local_login(self, data):
        username = data['username']
        password = data['password']
        with ldap_context(self.ldap_settings, use_cache=False):
            try:
                user_dn, user_data = get_user_by_id(username, attributes=[self.ldap_settings['uid']])
                if not user_dn:
                    raise NoSuchUser(provider=self)
                current_ldap.connection.simple_bind_s(user_dn, password)
            except INVALID_CREDENTIALS:
                raise InvalidCredentials(provider=self)
        auth_info = AuthInfo(self, identifier=user_data[self.ldap_settings['uid']][0])
        return self.multipass.handle_auth_success(auth_info)


class LDAPGroup(Group):
    """A group from the LDAP identity provider"""

    #: If it is possible to get the list of members of a group.
    supports_member_list = True

    def __init__(self, provider, name, dn):  # pragma: no cover
        super(LDAPGroup, self).__init__(provider, name)
        self.dn = dn

    @property
    def ldap_settings(self):  # pragma: no cover
        return self.provider.ldap_settings

    @property
    def settings(self):  # pragma: no cover
        return self.provider.settings

    def _iter_group(self):
        to_visit = set([self.dn])
        visited = set()
        while to_visit:
            next_group_dn = to_visit.pop()
            visited.add(next_group_dn)
            groups = yield next_group_dn
            if groups:
                to_visit.update({group_dn for group_dn, group_data in groups if group_dn not in visited})

    def get_members(self):
        with ldap_context(self.ldap_settings):
            group_dns = self._iter_group()
            group_dn = next(group_dns)
            while group_dn:
                user_filter = build_user_search_filter({self.ldap_settings['member_of_attr']: {group_dn}}, exact=True)
                for _, user_data in self.provider._search_users(user_filter):
                    user_data = to_unicode(user_data)
                    yield IdentityInfo(self.provider, identifier=user_data[self.ldap_settings['uid']][0], **user_data)
                group_filter = build_group_search_filter({self.ldap_settings['member_of_attr']: {group_dn}}, exact=True)
                subgroups = list(self.provider._search_groups(group_filter))
                try:
                    group_dn = group_dns.send(subgroups)
                except StopIteration:
                    break

    def has_member(self, user_identifier):
        with ldap_context(self.ldap_settings):
            user_dn, user_data = get_user_by_id(user_identifier, attributes=[self.ldap_settings['member_of_attr']])
            if not user_dn:
                return False
            if self.ldap_settings['ad_group_style']:
                group_dn, group_data = get_group_by_id(self.name, attributes=['objectSid'])
                group_sids = group_data.get('objectSid')
                token_groups = get_token_groups_from_user_dn(user_dn)
                return any(group_sid in token_groups for group_sid in group_sids)
            else:
                return self.dn in user_data.get(self.ldap_settings['member_of_attr'], [])


class LDAPIdentityProvider(LDAPProviderMixin, IdentityProvider):
    """Provides identity information using LDAP."""

    #: If the provider supports refreshing user information
    supports_refresh = True
    #: If the provider supports searching users
    supports_search = True
    #: If the provider also provides groups and membership information
    supports_groups = True
    #: The class that represents groups from this provider
    group_class = LDAPGroup

    def __init__(self, *args, **kwargs):
        super(LDAPIdentityProvider, self).__init__(*args, **kwargs)
        self.set_defaults()
        self.ldap_settings.setdefault('gid', 'cn')
        self.ldap_settings.setdefault('group_filter', '(objectClass=groupOfNames)')
        self.ldap_settings.setdefault('member_of_attr', 'memberOf')
        self.ldap_settings.setdefault('ad_group_style', False)
        self.settings['mapping'] = to_unicode(self.settings['mapping'])
        self._attributes = list(
            convert_app_data(self.settings['mapping'], {}, self.settings['identity_info_keys']).values())
        self._attributes.append(self.ldap_settings['uid'])

    @property
    def supports_get_identity_groups(self):
        return self.ldap_settings['ad_group_style']

    def _get_identity(self, identifier):
        with ldap_context(self.ldap_settings):
            user_dn, user_data = get_user_by_id(identifier, self._attributes)
        if not user_dn:
            return None
        user_data = to_unicode(user_data)
        return IdentityInfo(self, identifier=user_data[self.ldap_settings['uid']][0], **user_data)

    def _search_users(self, search_filter):  # pragma: no cover
        return search(self.ldap_settings['user_base'], search_filter, self._attributes)

    def _search_groups(self, search_filter):  # pragma: no cover
        return search(self.ldap_settings['group_base'], search_filter, attributes=[self.ldap_settings['gid']])

    def get_identity_from_auth(self, auth_info):  # pragma: no cover
        return self._get_identity(auth_info.data.pop('identifier'))

    def refresh_identity(self, identifier, multipass_data):  # pragma: no cover
        return self._get_identity(identifier)

    def get_identity(self, identifier):  # pragma: no cover
        return self._get_identity(identifier)

    def search_identities(self, criteria, exact=False):
        with ldap_context(self.ldap_settings):
            search_filter = build_user_search_filter(criteria, self.settings['mapping'], exact=exact)
            if not search_filter:
                raise IdentityRetrievalFailed("Unable to generate search filter from criteria", provider=self)
            for _, user_data in self._search_users(search_filter):
                user_data = to_unicode(user_data)
                yield IdentityInfo(self, identifier=user_data[self.ldap_settings['uid']][0], **user_data)

    def get_identity_groups(self, identifier):
        groups = set()
        with ldap_context(self.ldap_settings):
            user_dn, user_data = get_user_by_id(identifier, self._attributes)
            if not user_dn:
                return set()
            if self.ldap_settings['ad_group_style']:
                for sid in get_token_groups_from_user_dn(user_dn):
                    search_filter = build_group_search_filter({'objectSid': {sid}}, exact=True)
                    for group_dn, group_data in self._search_groups(search_filter):
                        group_name = to_unicode(group_data[self.ldap_settings['gid']][0])
                        groups.add(self.group_class(self, group_name, group_dn))
            else:
                # OpenLDAP does not have a way to get all groups for a user including nested ones
                raise NotImplementedError('Only available for active directory')
        return groups

    def get_group(self, name):
        with ldap_context(self.ldap_settings):
            group_dn, group_data = get_group_by_id(name, [self.ldap_settings['gid']])
        if not group_dn:
            return None
        group_name = to_unicode(group_data[self.ldap_settings['gid']][0])
        return self.group_class(self, group_name, group_dn)

    def search_groups(self, name, exact=False):
        with ldap_context(self.ldap_settings):
            search_filter = build_group_search_filter({self.ldap_settings['gid']: {name}}, exact=exact)
            if not search_filter:
                raise GroupRetrievalFailed("Unable to generate search filter from criteria", provider=self)
            for group_dn, group_data in self._search_groups(search_filter):
                group_name = to_unicode(group_data[self.ldap_settings['gid']][0])
                yield self.group_class(self, group_name, group_dn)
