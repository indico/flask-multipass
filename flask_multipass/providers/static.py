# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import itertools
import operator

from wtforms.fields import StringField, PasswordField
from wtforms.validators import DataRequired

from flask_multipass._compat import iteritems, FlaskForm
from flask_multipass.auth import AuthProvider
from flask_multipass.data import AuthInfo, IdentityInfo
from flask_multipass.exceptions import NoSuchUser, InvalidCredentials
from flask_multipass.group import Group
from flask_multipass.identity import IdentityProvider


class StaticLoginForm(FlaskForm):
    username = StringField('Username', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])


class StaticAuthProvider(AuthProvider):
    """Provides authentication against a static list

    This provider should NEVER be use in any production system.
    It serves mainly as a simple dummy/example for development.

    The type name to instantiate this provider is *static*.
    """

    login_form = StaticLoginForm

    def __init__(self, *args, **kwargs):
        super(StaticAuthProvider, self).__init__(*args, **kwargs)
        self.settings.setdefault('identities', {})

    def process_local_login(self, data):
        username = data['username']
        password = self.settings['identities'].get(username)
        if password is None:
            raise NoSuchUser(provider=self)
        if password != data['password']:
            raise InvalidCredentials(provider=self)
        auth_info = AuthInfo(self, username=data['username'])
        return self.multipass.handle_auth_success(auth_info)


class StaticGroup(Group):
    """A group from the static identity provider"""

    supports_member_list = True

    def get_members(self):
        members = self.provider.settings['groups'][self.name]
        for username in members:
            yield self.provider._get_identity(username)

    def has_member(self, identifier):
        return identifier in self.provider.settings['groups'][self.name]


class StaticIdentityProvider(IdentityProvider):
    """Provides identity information from a static list.

    This provider should NEVER be use in any production system.
    It serves mainly as a simple dummy/example for development.

    The type name to instantiate this provider is *static*.
    """

    #: If the provider supports refreshing user information
    supports_refresh = True
    #: If the provider supports searching identities
    supports_search = True
    #: If the provider also provides groups and membership information
    supports_groups = True
    #: If the provider supports getting the list of groups an identity belongs to
    supports_get_identity_groups = True
    #: The class that represents groups from this provider
    group_class = StaticGroup

    def __init__(self, *args, **kwargs):
        super(StaticIdentityProvider, self).__init__(*args, **kwargs)
        self.settings.setdefault('identities', {})
        self.settings.setdefault('groups', {})

    def _get_identity(self, identifier):
        user = self.settings['identities'].get(identifier)
        if user is None:
            return None
        return IdentityInfo(self, identifier, **user)

    def get_identity_from_auth(self, auth_info):
        identifier = auth_info.data['username']
        return self._get_identity(identifier)

    def refresh_identity(self, identifier, multipass_data):
        return self._get_identity(identifier)

    def get_identity(self, identifier):
        return self._get_identity(identifier)

    def search_identities(self, criteria, exact=False):
        for identifier, user in iteritems(self.settings['identities']):
            for key, values in iteritems(criteria):
                # same logic as multidict
                user_value = user.get(key)
                user_values = set(user_value) if isinstance(user_value, (tuple, list)) else {user_value}
                if not any(user_values):
                    break
                elif exact and not user_values & set(values):
                    break
                elif not exact and not any(sv in uv for sv, uv in itertools.product(values, user_values)):
                    break
            else:
                yield IdentityInfo(self, identifier, **user)

    def get_identity_groups(self, identifier):
        groups = set()
        for group_name in self.settings['groups']:
            group = self.get_group(group_name)
            if identifier in group:
                groups.add(group)
        return groups

    def get_group(self, name):
        if name not in self.settings['groups']:
            return None
        return self.group_class(self, name)

    def search_groups(self, name, exact=False):
        compare = operator.eq if exact else operator.contains
        for group_name in self.settings['groups']:
            if compare(group_name, name):
                yield self.group_class(self, group_name)
