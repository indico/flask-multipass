# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import absolute_import

from flask_wtf import Form
from ldap import INVALID_CREDENTIALS
from wtforms.fields import StringField, PasswordField
from wtforms.validators import DataRequired

from flask_multiauth.auth import AuthProvider
from flask_multiauth.data import AuthInfo, IdentityInfo
from flask_multiauth.exceptions import NoSuchUser, InvalidCredentials, IdentityRetrievalFailed, GroupRetrievalFailed
from flask_multiauth.group import Group
from flask_multiauth.identity import IdentityProvider
from flask_multiauth.util import map_app_data

from flask_multiauth.providers.ldap.globals import current_ldap
from flask_multiauth.providers.ldap.operations import (build_user_search_filter, build_group_search_filter,
                                                       get_user_by_id, get_group_by_id, get_token_groups_from_user_dn,
                                                       search)
from flask_multiauth.providers.ldap.util import ldap_context


class LoginForm(Form):
    username = StringField('Username', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])


class LDAPProviderMixin(object):
    @property
    def ldap_settings(self):
        return self.settings['ldap']

    def set_defaults(self):
        self.ldap_settings.setdefault('timeout', 30)
        self.ldap_settings.setdefault('tls', True)
        self.ldap_settings.setdefault('starttls', False)
        self.ldap_settings.setdefault('page_size', 1000)
        self.ldap_settings.setdefault('uid', 'uid')
        self.ldap_settings.setdefault('user_filter', '(objectClass=person)')


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
        with ldap_context(self.ldap_settings):
            try:
                user_dn, user_data = get_user_by_id(username, attributes=[self.ldap_settings['uid']])
                if not user_dn:
                    raise NoSuchUser()
                current_ldap.connection.simple_bind_s(user_dn, password)
            except INVALID_CREDENTIALS:
                raise InvalidCredentials()
        return AuthInfo(self, identifier=user_data[self.ldap_settings['uid']][0])


class LDAPGroup(Group):
    """A group from the LDAP identity provider"""

    #: If it is possible to get the list of members of a group.
    supports_member_list = True

    def __init__(self, provider, name, dn):  # pragma: no cover
        super(LDAPGroup, self).__init__(provider, name)
        self.dn = dn

    @property
    def ldap_settings(self):
        return self.provider.ldap_settings

    @property
    def settings(self):
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
                # 'generator.send' returns the next value to be yield,
                # which is not the desired behaviour here as the
                # generator is used in a loop, so we yield 'None' to
                # the 'generator.send' call in order to get the next
                # value in the loop.
                yield None

    def get_members(self):
        with ldap_context(self.ldap_settings):
            group_dns = self._iter_group()
            for group_dn in group_dns:
                user_filter = build_user_search_filter({self.ldap_settings['member_of_attr']: group_dn}, exact=True)
                for _, user_data in self.provider._search_users(user_filter):
                    yield IdentityInfo(self.provider, identifier=user_data[self.ldap_settings['uid']][0], **user_data)
                group_filter = build_group_search_filter({self.ldap_settings['member_of_attr']: group_dn}, exact=True)
                group_dns.send(self.provider._search_groups(group_filter))

    def has_user(self, user_identifier):
        with ldap_context(self.ldap_settings):
            user_dn, user_data = get_user_by_id(user_identifier, attributes=[self.ldap_settings['member_of_attr']])
            if not user_dn:
                raise IdentityRetrievalFailed()
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
        self._attributes = map_app_data(self.settings['mapping'], {}, self.settings['identity_info_keys']).values()
        self._attributes.append(self.ldap_settings['uid'])

    def _get_identity(self, identifier):
        with ldap_context(self.ldap_settings):
            user_dn, user_data = get_user_by_id(identifier, self._attributes)
        if not user_dn:
            return None
        return IdentityInfo(self, identifier=user_data[self.ldap_settings['uid']][0], **user_data)

    def _search_users(self, search_filter):
        return search(self.ldap_settings['user_base'], search_filter, self._attributes)

    def _search_groups(self, search_filter):
        return search(self.ldap_settings['group_base'], search_filter, attributes=[self.ldap_settings['gid']])

    def get_identity_from_auth(self, auth_info):
        return self._get_identity(auth_info.data.pop('identifier'))

    def refresh_identity(self, identifier, multiauth_data):
        return self._get_identity(identifier)

    def search_identities(self, criteria, exact=False):
        with ldap_context(self.ldap_settings):
            search_filter = build_user_search_filter(criteria, self.settings['mapping'], exact=exact)
            if not search_filter:
                raise IdentityRetrievalFailed("Unable to generate search filter from criteria")
            for _, user_data in self._search_users(search_filter):
                yield IdentityInfo(self, identifier=user_data[self.ldap_settings['uid']][0], **user_data)

    def get_group(self, name):
        with ldap_context(self.ldap_settings):
            group_dn, group_data = get_group_by_id(name)
        if not group_dn:
            return None
        return self.group_class(self, group_data.get(self.ldap_settings['gid'])[0], group_dn)

    def search_groups(self, name, exact=False):
        with ldap_context(self.ldap_settings):
            search_filter = build_group_search_filter({self.ldap_settings['gid']: name}, exact=exact)
            if not search_filter:
                raise GroupRetrievalFailed("Unable to generate search filter from criteria")
            for group_dn, group_data in self._search_groups(search_filter):
                yield self.group_class(self, group_data.get(self.ldap_settings['gid'])[0], group_dn)
