# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from unittest.mock import MagicMock

import pytest
from flask import Flask
from ldap import INVALID_CREDENTIALS

from flask_multipass import Multipass
from flask_multipass.exceptions import IdentityRetrievalFailed, InvalidCredentials, NoSuchUser
from flask_multipass.providers.ldap import LDAPAuthProvider, LDAPGroup, LDAPIdentityProvider


@pytest.mark.parametrize(('settings', 'data'), (
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid',
    }}, {'username': 'alaindi', 'password': 'LemotdepassedeLDAP'}),
))
def test_authenticate(mocker, settings, data):
    def user_dn(user):
        return f'dn={user},dc=example,dc=com'
    mocker.patch('flask_multipass.providers.ldap.providers.get_user_by_id',
                 return_value=(user_dn(data['username']), {settings['ldap']['uid']: [data['username']]}))
    ldap_conn = MagicMock(simple_bind_s=MagicMock())
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject', return_value=ldap_conn)

    multipass = MagicMock()
    auth_provider = LDAPAuthProvider(multipass, 'LDAP test provider', settings)
    auth_provider.process_local_login(data)
    ldap_conn.simple_bind_s.assert_called_with(user_dn(data['username']), data['password'])
    auth_info = multipass.handle_auth_success.call_args[0][0]
    assert auth_info.data['identifier'] == data['username']


@pytest.mark.parametrize(('settings', 'data'), (
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid',
    }}, {'username': 'alaindi', 'password': 'LemotdepassedeLDAP'}),
))
def test_authenticate_invalid_user(mocker, settings, data):
    mocker.patch('flask_multipass.providers.ldap.providers.get_user_by_id',
                 return_value=(None, {'cn': ['Configuration']}))
    ldap_conn = MagicMock(simple_bind_s=MagicMock())
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject', return_value=ldap_conn)

    auth_provider = LDAPAuthProvider(None, 'LDAP test provider', settings)
    with pytest.raises(NoSuchUser):
        auth_provider.process_local_login(data)


@pytest.mark.parametrize(('settings', 'data'), (
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid',
    }}, {'username': 'alaindi', 'password': 'LemotdepassedeLDAP'}),
))
def test_authenticate_invalid_credentials(mocker, settings, data):
    def user_dn(user):
        return f'dn={user},dc=example,dc=com'
    mocker.patch('flask_multipass.providers.ldap.providers.get_user_by_id',
                 return_value=(user_dn(data['username']), {settings['ldap']['uid']: [data['username']]}))
    ldap_conn = MagicMock(simple_bind_s=MagicMock(side_effect=[None, INVALID_CREDENTIALS]))
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject', return_value=ldap_conn)

    auth_provider = LDAPAuthProvider(None, 'LDAP test provider', settings)
    with pytest.raises(InvalidCredentials):
        auth_provider.process_local_login(data)
    ldap_conn.simple_bind_s.assert_called_with(user_dn(data['username']), data['password'])


@pytest.mark.parametrize(('settings', 'group_dn', 'subgroups', 'expected'), (
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
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
        'verify_cert': True,
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
        'verify_cert': True,
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
    multipass = Multipass(app)
    with app.app_context():
        idp = LDAPIdentityProvider(multipass, 'LDAP test idp', settings)
    group = LDAPGroup(idp, 'LDAP test group', group_dn)
    visited_groups = []
    iter_group = group._iter_group()
    # should not throw StopIteration as the initial group dn must be returned first
    current_dn = next(iter_group)
    with pytest.raises(StopIteration):  # noqa: PT012
        while current_dn:
            visited_groups.append(current_dn)
            current_dn = iter_group.send(subgroups.get(current_dn, []))

    assert len(visited_groups) == len(expected)
    assert set(visited_groups) == expected


@pytest.mark.parametrize(('settings', 'group_dn', 'mock_data', 'expected'), (
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid'}},
     'group_dn_1',
     {'groups': ['group_dn_1'], 'subgroups': {}, 'users': {}},
     []),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid'}},
     'group_dn_1',
     {'groups': ['group_dn_1'], 'subgroups': {},
      'users': {'group_dn_1': [('user_1', {'uid': ['user_1']}), ('user_2', {'uid': ['user_2']})]}},
     ['user_1', 'user_2']),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid'}},
     'group_dn_1',
     {'groups': ['group_dn_1', 'group_dn_1.1'],
      'subgroups': {'group_dn_1': [('group_dn_1.1', {})]},
      'users': {'group_dn_1': [('user_1', {'uid': ['user_1']}), ('user_2', {'uid': ['user_2']})],
                'group_dn_1.1': [('user_3', {'uid': ['user_3']}), ('user_4', {'uid': ['user_4']})]}},
     ['user_1', 'user_2', 'user_3', 'user_4']),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'uid': 'uid'}},
     'group_dn_1',
     {'groups': ['group_dn_1', 'group_dn_1.1', 'group_dn_1.1.1', 'group_dn_1.1.2'],
      'subgroups': {'group_dn_1': [('group_dn_1.1', {})]},
      'users': {'group_dn_1': [('user_1', {'uid': ['user_1']}), ('user_2', {'uid': ['user_2']})],
                'group_dn_1.1': [('user_3', {'uid': ['user_3']}), ('user_4', {'uid': ['user_4']})],
                'group_dn_1.1.2': [('user_5', {'uid': ['user_5']}), ('user_6', {'uid': ['user_6']})],
                'group_dn_1.1.3': [('user_7', {'uid': ['user_7']}), ('user_8', {'uid': ['user_8']})]}},
     ['user_1', 'user_2', 'user_3', 'user_4', 'user_5', 'user_6', 'user_7', 'user_8']),
))
def test_get_members(mocker, settings, group_dn, mock_data, expected):
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject')
    mocker.patch('flask_multipass.providers.ldap.providers.build_group_search_filter',
                 side_effect=MagicMock(side_effect=mock_data['groups']))
    mocker.patch('flask_multipass.providers.ldap.providers.build_user_search_filter',
                 side_effect=MagicMock(side_effect=mock_data['groups']))
    app = Flask('test')
    multipass = Multipass(app)
    with app.app_context():
        idp = LDAPIdentityProvider(multipass, 'LDAP test idp', settings)

    idp._search_groups = MagicMock(side_effect=lambda x: mock_data['subgroups'].get(x, []))
    idp._search_users = MagicMock(side_effect=lambda x: mock_data['users'].get(x, []))
    group = LDAPGroup(idp, 'LDAP test group', group_dn)

    with pytest.raises(StopIteration):  # noqa: PT012
        members = group.get_members()
        while True:
            member = next(members)
            assert member.provider.name == idp.name
            assert member.identifier == expected.pop(0)


@pytest.mark.parametrize(('settings', 'group_mock', 'user_mock', 'expected'), (
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': True,
        'uid': 'uid'}},
     {'dn': 'group_dn', 'data': {'objectSid': []}},
     {'dn': 'user_dn', 'data': {'uid': ['user_uid']}, 'token_groups': []},
     False),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': True,
        'uid': 'uid'}},
     {'dn': 'group_dn', 'data': {'objectSid': ['group_token<001>']}},
     {'dn': 'user_dn', 'data': {'uid': ['user_uid']}, 'token_groups': ['group_token<001>']},
     True),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': True,
        'uid': 'uid'}},
     {'dn': 'group_dn', 'data': {'objectSid': ['group_token<002>']}},
     {'dn': 'user_dn', 'data': {'uid': ['user_uid']}, 'token_groups': ['group_token<001>', 'group_token<003>']},
     False),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': True,
        'uid': 'uid'}},
     {'dn': 'group_dn', 'data': {'objectSid': ['group_token<002>']}},
     {'dn': 'user_dn', 'data': {'uid': ['user_uid']}, 'token_groups': ['group_token<001>', 'group_token<002>',
                                                                       'group_token<003>']},
     True),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': True,
        'uid': 'uid'}},
     {'dn': 'group_dn', 'data': {'objectSid': ['group_token<001>', 'group_token<003>']}},
     {'dn': 'user_dn', 'data': {'uid': ['user_uid']}, 'token_groups': ['group_token<002>']},
     False),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': True,
        'uid': 'uid'}},
     {'dn': 'group_dn', 'data': {'objectSid': ['group_token<001>', 'group_token<002>', 'group_token<003>']}},
     {'dn': 'user_dn', 'data': {'uid': ['user_uid']}, 'token_groups': ['group_token<002>']},
     True),
))
def test_has_member_ad(mocker, settings, group_mock, user_mock, expected):
    def get_token_groups(user_dn):
        if user_mock['dn'] != user_dn:
            pytest.fail('expected {}, got {}'.format(user_mock['dn'], user_dn))
        return user_mock['token_groups']
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject')
    mocker.patch('flask_multipass.providers.ldap.providers.get_user_by_id',
                 return_value=(user_mock['dn'], user_mock['data']))
    mocker.patch('flask_multipass.providers.ldap.providers.get_group_by_id',
                 return_value=(group_mock['dn'], group_mock['data']))
    mocker.patch('flask_multipass.providers.ldap.providers.get_token_groups_from_user_dn', side_effect=get_token_groups)

    app = Flask('test')
    multipass = Multipass(app)
    with app.app_context():
        idp = LDAPIdentityProvider(multipass, 'LDAP test idp', settings)
    group = LDAPGroup(idp, 'LDAP test group', group_mock['dn'])
    assert group.has_member(user_mock['data']['uid'][0]) == expected


@pytest.mark.parametrize(('settings', 'group_dn', 'user_mock', 'expected'), (
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': False,
        'uid': 'uid',
        'member_of_attr': 'member_of'}},
     'group_dn',
     {'dn': 'user_dn', 'data': {'uid': ['user_uid'], 'member_of': []}},
     False),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': False,
        'uid': 'uid',
        'member_of_attr': 'member_of'}},
     'group_dn',
     {'dn': 'user_dn', 'data': {'uid': ['user_uid'], 'member_of': ['other_group_dn']}},
     False),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': False,
        'uid': 'uid',
        'member_of_attr': 'member_of'}},
     'group_dn',
     {'dn': 'user_dn', 'data': {'uid': ['user_uid'], 'member_of': ['group_dn']}},
     True),
    ({'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': False,
        'uid': 'uid',
        'member_of_attr': 'member_of'}},
     'group_dn',
     {'dn': 'user_dn', 'data': {'uid': ['user_uid'], 'member_of': ['other_group_dn', 'group_dn']}},
     True),
))
def test_has_member_slapd(mocker, settings, group_dn, user_mock, expected):
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject')
    mocker.patch('flask_multipass.providers.ldap.providers.get_user_by_id',
                 return_value=(user_mock['dn'], user_mock['data']))

    app = Flask('test')
    multipass = Multipass(app)
    with app.app_context():
        idp = LDAPIdentityProvider(multipass, 'LDAP test idp', settings)
    group = LDAPGroup(idp, 'LDAP test group', group_dn)
    assert group.has_member(user_mock['data']['uid'][0]) == expected


@pytest.mark.parametrize('settings', (
    {'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': True,
        'uid': 'uid',
        'member_of_attr': 'member_of'}},
    {'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': False,
        'uid': 'uid',
        'member_of_attr': 'member_of'}},
))
def test_has_member_bad_identifier(mocker, settings):
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject')
    app = Flask('test')
    multipass = Multipass(app)
    with app.app_context():
        idp = LDAPIdentityProvider(multipass, 'LDAP test idp', settings)
    group = LDAPGroup(idp, 'LDAP test group', 'group_dn')

    with pytest.raises(IdentityRetrievalFailed):
        group.has_member(None)


@pytest.mark.parametrize('settings', (
    {'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': True,
        'uid': 'uid',
        'member_of_attr': 'member_of'}},
    {'ldap': {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'starttls': True,
        'timeout': 10,
        'ad_group_style': False,
        'uid': 'uid',
        'member_of_attr': 'member_of'}},
))
def test_has_member_unknown_user(mocker, settings):
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject')
    mocker.patch('flask_multipass.providers.ldap.providers.get_user_by_id',
                 return_value=(None, {'cn': ['Configuration']}))
    app = Flask('test')
    multipass = Multipass(app)
    with app.app_context():
        idp = LDAPIdentityProvider(multipass, 'LDAP test idp', settings)
    group = LDAPGroup(idp, 'LDAP test group', 'group_dn')

    assert not group.has_member('unknown_user')


@pytest.mark.parametrize(('required_settings', 'expected_settings'), (
    ({'uri': 'ldaps://required.uri',
      'bind_dn': 'uid=admin,OU=Users,OU=Required,DC=example,DC=com',
      'bind_password': 'required_password',
      'user_base': 'OU=Users,OU=Required,DC=example,DC=com'},
     {'uri': 'ldaps://required.uri',
      'bind_dn': 'uid=admin,OU=Users,OU=Required,DC=example,DC=com',
      'bind_password': 'required_password',
      'timeout': 30,
      'verify_cert': True,
      'cert_file': '/default/ca-certs-file',
      'starttls': False,
      'page_size': 1000,
      'uid': 'uid',
      'user_base': 'OU=Users,OU=Required,DC=example,DC=com',
      'user_filter': '(objectClass=person)'}),
    ({'uri': 'ldaps://required.uri',
      'bind_dn': 'uid=admin,OU=Users,OU=Required,DC=example,DC=com',
      'bind_password': 'required_password',
      'user_base': 'OU=Users,OU=Required,DC=example,DC=com',
      'timeout': 25,
      'verify_cert': False,
      'cert_file': '/custom/ca-certs-file'},
     {'uri': 'ldaps://required.uri',
      'bind_dn': 'uid=admin,OU=Users,OU=Required,DC=example,DC=com',
      'bind_password': 'required_password',
      'timeout': 25,
      'verify_cert': False,
      'cert_file': '/custom/ca-certs-file',
      'starttls': False,
      'page_size': 1000,
      'uid': 'uid',
      'user_base': 'OU=Users,OU=Required,DC=example,DC=com',
      'user_filter': '(objectClass=person)'}),
))
def test_default_authp_settings(mocker, required_settings, expected_settings):
    certifi = mocker.patch('flask_multipass.providers.ldap.providers.certifi')
    certifi.where.return_value = '/default/ca-certs-file'
    multipass = MagicMock()
    authp = LDAPAuthProvider(multipass, 'LDAP test provider', {'ldap': required_settings})
    assert authp.ldap_settings == expected_settings


@pytest.mark.parametrize(('required_settings', 'expected_settings'), (
    ({'uri': 'ldaps://required.uri',
      'bind_dn': 'uid=admin,OU=Users,OU=Required,DC=example,DC=com',
      'bind_password': 'required_password',
      'user_base': 'OU=Users,OU=Required,DC=example,DC=com',
      'group_base': 'OU=Groups,OU=Required,DC=example,DC=com'},
     {'uri': 'ldaps://required.uri',
      'bind_dn': 'uid=admin,OU=Users,OU=Required,DC=example,DC=com',
      'bind_password': 'required_password',
      'timeout': 30,
      'verify_cert': True,
      'cert_file': '/default/ca-certs-file',
      'starttls': False,
      'page_size': 1000,
      'uid': 'uid',
      'user_base': 'OU=Users,OU=Required,DC=example,DC=com',
      'user_filter': '(objectClass=person)',
      'gid': 'cn',
      'group_base': 'OU=Groups,OU=Required,DC=example,DC=com',
      'group_filter': '(objectClass=groupOfNames)',
      'member_of_attr': 'memberOf',
      'ad_group_style': False}),
    ({'uri': 'ldaps://required.uri',
      'bind_dn': 'uid=admin,OU=Users,OU=Required,DC=example,DC=com',
      'bind_password': 'required_password',
      'user_base': 'OU=Users,OU=Required,DC=example,DC=com',
      'group_base': 'OU=Groups,OU=Required,DC=example,DC=com',
      'timeout': 25,
      'verify_cert': True,
      'cert_file': '/custom/ca-certs-file',
      'group_filter': '(|(objectClass=groupOfNames)(objectClass=custom))',
      'member_of_attr': 'member_of',
      'ad_group_style': True},
     {'uri': 'ldaps://required.uri',
      'bind_dn': 'uid=admin,OU=Users,OU=Required,DC=example,DC=com',
      'bind_password': 'required_password',
      'timeout': 25,
      'verify_cert': True,
      'cert_file': '/custom/ca-certs-file',
      'starttls': False,
      'page_size': 1000,
      'uid': 'uid',
      'user_base': 'OU=Users,OU=Required,DC=example,DC=com',
      'user_filter': '(objectClass=person)',
      'gid': 'cn',
      'group_base': 'OU=Groups,OU=Required,DC=example,DC=com',
      'group_filter': '(|(objectClass=groupOfNames)(objectClass=custom))',
      'member_of_attr': 'member_of',
      'ad_group_style': True}),
))
def test_default_idp_settings(mocker, required_settings, expected_settings):
    certifi = mocker.patch('flask_multipass.providers.ldap.providers.certifi')
    certifi.where.return_value = '/default/ca-certs-file'
    app = Flask('test')
    multipass = Multipass(app)
    with app.app_context():
        idp = LDAPIdentityProvider(multipass, 'LDAP test idp', {'ldap': required_settings})
    assert idp.ldap_settings == expected_settings
