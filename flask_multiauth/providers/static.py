# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import operator

from flask_wtf import Form
from wtforms.fields import StringField, PasswordField
from wtforms.validators import DataRequired

from flask_multiauth._compat import iteritems
from flask_multiauth.auth import AuthProvider
from flask_multiauth.data import AuthInfo, UserInfo
from flask_multiauth.exceptions import AuthenticationFailed
from flask_multiauth.group import Group
from flask_multiauth.user import UserProvider


class StaticLoginForm(Form):
    username = StringField('Username', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])


class StaticAuthProvider(AuthProvider):
    """Provides authentication against a static list

    This provider should NEVER be use in any production system.
    It serves mainly as a simply dummy/example for development.
    """

    #: The type to use in the auth provider config.
    type = 'static'
    login_form = StaticLoginForm

    def __init__(self, *args, **kwargs):
        super(StaticAuthProvider, self).__init__(*args, **kwargs)
        self.settings.setdefault('users', {})

    def process_local_login(self, data):
        username = data['username']
        password = self.settings['users'].get(username)
        if password is None:
            raise AuthenticationFailed('No such user')
        if password != data['password']:
            raise AuthenticationFailed('Invalid password.')
        return AuthInfo(self, username=data['username'])


class StaticUserProvider(UserProvider):
    """Provides user information from a static list.

    This provider should NEVER be use in any production system.
    It serves mainly as a simply dummy/example for development.
    """

    #: The type to use in the user provider config.
    type = 'static'
    #: If the provider supports refreshing user information
    supports_refresh = True
    #: If the provider supports searching users
    supports_search = True
    #: If the provider also provides groups and membership information
    has_groups = True

    def __init__(self, *args, **kwargs):
        super(StaticUserProvider, self).__init__(*args, **kwargs)
        self.settings.setdefault('users', {})
        self.settings.setdefault('groups', {})

    def _get_user(self, identifier):
        user = self.settings['users'].get(identifier)
        if user is None:
            return None
        return UserInfo(self, identifier, **user)

    def get_user_from_auth(self, auth_info):
        identifier = auth_info.data['username']
        return self._get_user(identifier)

    def refresh_user(self, identifier, multiauth_data):
        return self._get_user(identifier)

    def search_users(self, criteria, exact=False):
        compare = operator.eq if exact else operator.contains
        for identifier, user in iteritems(self.settings['users']):
            for key, value in iteritems(criteria):
                if not compare(user[key], value):
                    break
            else:
                yield UserInfo(self, identifier, **user)

    def get_group(self, name):
        if name not in self.settings['groups']:
            return None
        return StaticGroup(self, name)

    def search_groups(self, name, exact=False):
        compare = operator.eq if exact else operator.contains
        for group_name in self.settings['groups']:
            if compare(group_name, name):
                yield StaticGroup(self, group_name)


class StaticGroup(Group):
    """A group from the static user provider"""

    supports_user_list = True

    def get_users(self):
        members = self.provider.settings['groups'][self.name]
        for username in members:
            yield self.provider._get_user(username)

    def has_user(self, identifier):
        return identifier in self.provider.settings['groups'][self.name]
