# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals


import pytest
from flask import Flask
from ldap import INVALID_CREDENTIALS
from mock import MagicMock

from flask_multiauth import MultiAuth
from flask_multiauth.exceptions import InvalidCredentials, NoSuchUser
from flask_multiauth.providers.ldap import LDAPAuthProvider, LDAPGroup, LDAPIdentityProvider


@pytest.mark.parametrize(('settings', 'data'), (
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'tls': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid'
    }}, {'username': 'alaindi', 'password': 'LemotdepassedeLDAP'}),
))
def test_authenticate(mocker, settings, data):
    user_dn = lambda user: 'dn={0},dc=example,dc=com'.format(user)
    mocker.patch('flask_multiauth.providers.ldap.providers.get_user_by_id',
                 return_value=(user_dn(data['username']), {settings['ldap']['uid']: [data['username']]}))
    ldap_conn = MagicMock(simple_bind_s=MagicMock())
    mocker.patch('flask_multiauth.providers.ldap.util.ldap.initialize', return_value=ldap_conn)

    auth_provider = LDAPAuthProvider(None, 'LDAP test provider', settings)
    auth_info = auth_provider.process_local_login(data)
    ldap_conn.simple_bind_s.assert_called_with(user_dn(data['username']), data['password'])
    assert auth_info.data['identifier'] == data['username']


@pytest.mark.parametrize(('settings', 'data'), (
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'tls': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid'
    }}, {'username': 'alaindi', 'password': 'LemotdepassedeLDAP'}),
))
def test_authenticate_invalid_user(mocker, settings, data):
    mocker.patch('flask_multiauth.providers.ldap.providers.get_user_by_id',
                 return_value=(None, {'cn': ['Configuration']}))
    ldap_conn = MagicMock(simple_bind_s=MagicMock())
    mocker.patch('flask_multiauth.providers.ldap.util.ldap.initialize', return_value=ldap_conn)

    auth_provider = LDAPAuthProvider(None, 'LDAP test provider', settings)
    with pytest.raises(NoSuchUser):
        auth_provider.process_local_login(data)


@pytest.mark.parametrize(('settings', 'data'), (
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'tls': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid'
    }}, {'username': 'alaindi', 'password': 'LemotdepassedeLDAP'}),
))
def test_authenticate_invalid_credentials(mocker, settings, data):
    user_dn = lambda user: 'dn={0},dc=example,dc=com'.format(user)
    mocker.patch('flask_multiauth.providers.ldap.providers.get_user_by_id',
                 return_value=(user_dn(data['username']), {settings['ldap']['uid']: [data['username']]}))
    ldap_conn = MagicMock(simple_bind_s=MagicMock(side_effect=[None, INVALID_CREDENTIALS]))
    mocker.patch('flask_multiauth.providers.ldap.util.ldap.initialize', return_value=ldap_conn)

    auth_provider = LDAPAuthProvider(None, 'LDAP test provider', settings)
    with pytest.raises(InvalidCredentials):
        auth_provider.process_local_login(data)
    ldap_conn.simple_bind_s.assert_called_with(user_dn(data['username']), data['password'])


@pytest.mark.parametrize(('settings', 'group_dn', 'subgroups', 'expected'), (
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'tls': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid'}},
     'group_dn_1',
     {},
     {'group_dn_1'}),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'tls': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid'}},
     'group_dn_1',
     {'group_dn_1': [('group_dn_1.1', {}), ('group_dn_1.2', {})]},
     {'group_dn_1', 'group_dn_1.1', 'group_dn_1.2'}),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'tls': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid'}},
     'group_dn_1',
     {'group_dn_1': [('group_dn_1.1', {}), ('group_dn_1.2', {})],
      'group_dn_1.2': [('group_dn_1.2.1', {})],
      'group_dn_1.2.1': [('group_dn_1.2.1.1', {}), ('group_dn_1.2.1.2', {}), ('group_dn_1.2.1.3', {})],
      'group_dn_1.2.1.3': []},
     {'group_dn_1', 'group_dn_1.1', 'group_dn_1.2', 'group_dn_1.2.1', 'group_dn_1.2.1.1', 'group_dn_1.2.1.2',
      'group_dn_1.2.1.3'}),
))
def test_iter_group(mocker, settings, group_dn, subgroups, expected):
    app = Flask('test')
    multiauth = MultiAuth(app)
    with app.app_context():
        idp = LDAPIdentityProvider(multiauth, 'LDAP test idp', settings)
    group = LDAPGroup(idp, 'LDAP test group', group_dn)
    visited_groups = []
    iter_group = group._iter_group()
    # should not throw StopIteration as the initial group dn must be returned first
    current_dn = next(iter_group)
    with pytest.raises(StopIteration):
        while current_dn:
            visited_groups.append(current_dn)
            current_dn = iter_group.send(subgroups.get(current_dn, []))

    assert len(visited_groups) == len(expected)
    assert set(visited_groups) == expected
