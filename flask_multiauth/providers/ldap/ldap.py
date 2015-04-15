from __future__ import absolute_import

from flask_wtf import Form
from ldap import INVALID_CREDENTIALS
from wtforms.fields import StringField, PasswordField
from wtforms.validators import DataRequired

from flask_multiauth.auth import AuthProvider, IdentityProvider
from flask_multiauth.data import AuthInfo, IdentityInfo
from flask_multiauth.exceptions import NoSuchUser, InvalidCredentials, IdentityRetrievalFailed, GroupRetrievalFailed
from flask_multiauth.group import Group
from flask_multiauth.util import map_app_data

from flask_multiauth.providers.ldap.globals import current_ldap
from flask_multiauth.providers.ldap.operations import (build_user_search_filter, build_group_search_filter,
                                                       get_user_by_id, get_group_by_id, get_token_groups_from_user_dn,
                                                       search)
from flask_multiauth.providers.ldap.util import ldap_context


class LoginForm(Form):
    identifier = StringField('Username', [DataRequired()])
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
        return AuthInfo(self, identifier=user_data[self.ldap_settings['uid']])


class LDAPGroup(Group):
    """A group from the LDAP identity provider"""

    def __init__(self, provider, name, dn):  # pragma: no cover
        super(LDAPGroup, self).__init__(provider, name)
        self.dn = dn

    @property
    def ldap_settings(self):
        return self.provider.ldap_settings

    def _iter_group(self):
        to_visit = set(self.dn)
        visited = set()

        while to_visit:
            next_group_dn = to_visit.pop()
            visited.add(next_group_dn)
            groups = yield next_group_dn
            to_visit.update({group_dn for group_dn, group_data in groups if group_dn not in visited})

    def get_members(self):
        with ldap_context(self.ldap_settings):
            group_dns = self._iter_group()
            for group_dn in group_dns:
                user_filter = build_user_search_filter({self.ldap_settings['member_of_attr']: group_dn}, exact=True)
                for _, user_data in search(self.ldap_settings['user_base'], user_filter, [self.ldap_settings['uid']]):
                    user_id = user_data.get(self.ldap_settings['uid'])
                    if user_id:
                        yield user_id[0]
                group_filter = build_group_search_filter({self.ldap_settings['member_of_attr']: group_dn}, exact=True)
                for groups in search(self.ldap_settings['group_base'], group_filter, [self.ldap_settings['gid']]):
                    group_dns.send(groups)

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

    def _get_identity(self, identifier):
        with ldap_context(self.ldap_settings):
            # TODO: get right attribute filter
            attributes = map_app_data(self.settings['mapping'], {}, self.settings['identity_info_keys']).values()
            attributes.append(self.ldap_settings['ldap']['uid'])
            user_dn, user_data = get_user_by_id(identifier, attributes)
        if not user_dn:
            return None
        return IdentityInfo(self, identifier=user_data[self.ldap_settings['uid']], **user_data)

    def get_user_from_auth(self, auth_info):
        return self._get_identity(auth_info.data.pop('identifier'))

    def refresh_identity(self, identifier, multiauth_data):
        return self._get_identity(identifier)

    def search_identities(self, criteria, exact=False):
        search_filter = build_user_search_filter(criteria, self.settings['mapping'], exact=exact)
        if not search_filter:
            raise IdentityRetrievalFailed("Unable to generate search filter from criteria")

        with ldap_context(self.ldap_settings):
            attributes = map_app_data(self.settings['mapping'], {}, self.settings['identity_info_keys']).values()
            for users in search(self.ldap_settings['user_base'], search_filter, attributes):
                for _, user_data in users:
                    yield IdentityInfo(self, identifier=user_data[self.ldap_settings['uid']], **user_data)

    def get_group(self, name):
        with ldap_context(self.ldap_settings):
            group_dn, group_data = get_group_by_id(name)
        if not group_dn:
            return None
        return self.group_class(self, group_data.get(self.ldap_settings['gid']), group_dn)

    def search_groups(self, name, exact=False):
        search_filter = build_group_search_filter({self.ldap_settings['gid']: name}, exact=exact)
        if not search_filter:
            raise GroupRetrievalFailed("Unable to generate search filter from criteria")

        with ldap_context(self.ldap_settings):
            for groups in search(self.ldap_settings['group_base'], search_filter, [self.ldap_settings['gid']]):
                for group_dn, group_data in groups:
                    yield self.group_class(group_data.get(self.ldap_settings['gid']), group_dn)
