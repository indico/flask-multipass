# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask_wtf import Form
from wtforms.fields import StringField, PasswordField
from wtforms.validators import DataRequired

from flask_multiauth.auth import AuthProvider
from flask_multiauth.data import AuthInfo, UserInfo
from flask_multiauth.exceptions import AuthenticationFailed
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

    def __init__(self, *args, **kwargs):
        super(StaticUserProvider, self).__init__(*args, **kwargs)
        self.settings.setdefault('users', {})

    def get_user_from_auth(self, auth_info):
        identifier = auth_info.data['username']
        user = self.settings['users'].get(identifier)
        if user is None:
            return None
        return UserInfo(self, identifier, **user)

    def refresh_user(self, identifier, refresh_data):
        user = self.settings['users'].get(identifier)
        if user is None:
            return None
        return UserInfo(self, identifier, **user)
