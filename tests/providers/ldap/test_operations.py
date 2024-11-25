# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from unittest.mock import MagicMock

import pytest
from ldap import NO_SUCH_OBJECT, SCOPE_BASE

from flask_multipass.exceptions import GroupRetrievalFailed, IdentityRetrievalFailed
from flask_multipass.providers.ldap.operations import (
    get_group_by_id,
    get_token_groups_from_user_dn,
    get_user_by_id,
    search,
)
from flask_multipass.providers.ldap.util import ldap_context


def test_get_user_by_id_handles_none_id():
    with pytest.raises(IdentityRetrievalFailed) as excinfo:
        get_user_by_id(None)
    assert str(excinfo.value) == 'No identifier specified'


def test_get_group_by_id_handles_none_id():
    with pytest.raises(GroupRetrievalFailed) as excinfo:
        get_group_by_id(None)
    assert str(excinfo.value) == 'No identifier specified'


@pytest.mark.parametrize(('settings', 'base_dn', 'search_filter', 'attributes', 'mock_data', 'expected'), (
    ({'uri': 'ldaps://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'verify_cert': True,
      'cert_file': ' /etc/ssl/certs/ca-certificates.crt',
      'starttls': True,
      'timeout': 10,
      'page_size': 3},
     'dc=example,dc=com', '(&(name=Alain)(objectCategory=user))', ['mail'],
     {'msg_ids': [f'msg_id<{i}>' for i in range(3)],
      'cookies': [f'cookie<{i}>' for i in range(2)],
      'results': ((('uid=alaina,dc=example,dc=com', {'mail': ['alaina@mail.com']}),
                   ('uid=alainb,dc=example,dc=com', {'mail': ['alainb@mail.com']}),
                   ('uid=alainc,dc=example,dc=com', {'mail': ['alainc@mail.com']})),
                  (('uid=alaind,dc=example,dc=com', {'mail': ['alaind@mail.com']}),
                   ('uid=alaine,dc=example,dc=com', {'mail': ['alaine@mail.com']}),
                   ('uid=alainf,dc=example,dc=com', {'mail': ['alainf@mail.com']})),
                  ((None, {'cn': ['Configuration']}),
                   ('uid=alaing,dc=example,dc=com', {'mail': ['alaing@mail.com']}),
                   ('uid=alainh,dc=example,dc=com', {'mail': ['alainh@mail.com']}),
                   ('uid=alaini,dc=example,dc=com', {'mail': ['alaini@mail.com']})))},
     (('uid=alaina,dc=example,dc=com', {'mail': ['alaina@mail.com']}),
      ('uid=alainb,dc=example,dc=com', {'mail': ['alainb@mail.com']}),
      ('uid=alainc,dc=example,dc=com', {'mail': ['alainc@mail.com']}),
      ('uid=alaind,dc=example,dc=com', {'mail': ['alaind@mail.com']}),
      ('uid=alaine,dc=example,dc=com', {'mail': ['alaine@mail.com']}),
      ('uid=alainf,dc=example,dc=com', {'mail': ['alainf@mail.com']}),
      ('uid=alaing,dc=example,dc=com', {'mail': ['alaing@mail.com']}),
      ('uid=alainh,dc=example,dc=com', {'mail': ['alainh@mail.com']}),
      ('uid=alaini,dc=example,dc=com', {'mail': ['alaini@mail.com']}))),
))
def test_search(mocker, settings, base_dn, search_filter, attributes, mock_data, expected):
    mock_data['cookies'].append('')  # last search operation should not return a cookie
    page_ctrl = MagicMock()
    mocker.patch('flask_multipass.providers.ldap.operations.SimplePagedResultsControl', return_value=page_ctrl)
    ldap_connection = MagicMock(result3=MagicMock(side_effect=((None, entries, None, [page_ctrl])
                                                               for entries in mock_data['results'])),
                                search_ext=MagicMock(side_effect=mock_data['msg_ids']))
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject', return_value=ldap_connection)
    mocker.patch('flask_multipass.providers.ldap.operations.get_page_cookie', side_effect=mock_data['cookies'])

    with ldap_context(settings):
        for i, result in enumerate(search(base_dn, search_filter, attributes)):
            assert result == expected[i]


@pytest.mark.parametrize(('settings', 'base_dn', 'search_filter', 'attributes', 'msg_ids'), (
    ({'uri': 'ldaps://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'verify_cert': True,
      'cert_file': ' /etc/ssl/certs/ca-certificates.crt',
      'starttls': True,
      'timeout': 10,
      'page_size': 3},
     'dc=example,dc=com',
     '(&(name=Alain)(objectCategory=user))',
     ['mail'],
     [f'msg_id<{i}>' for i in range(3)]),
))
def test_search_none_existing_entry(mocker, settings, base_dn, search_filter, attributes, msg_ids):
    page_ctrl = MagicMock()
    mocker.patch('flask_multipass.providers.ldap.operations.SimplePagedResultsControl', return_value=page_ctrl)
    ldap_connection = MagicMock(result3=MagicMock(side_effect=NO_SUCH_OBJECT),
                                search_ext=MagicMock(side_effect=msg_ids))
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject', return_value=ldap_connection)

    with ldap_context(settings):
        for _result in search(base_dn, search_filter, attributes):
            pytest.fail('search should not yield any result')


@pytest.mark.parametrize(('user_dn', 'mock_data', 'expected'), (
    ('cn=ielosubmarine,OU=Users,dc=example,dc=com',
     [('cn=ielosubmarine,OU=Users,dc=example,dc=com', {'tokenGroups': [f'token<{i}>' for i in range(5)]})],
     [f'token<{i}>' for i in range(5)]),
    ('cn=ielosubmarine,OU=Users,dc=example,dc=com',
     [('cn=ielosubmarine,OU=Users,dc=example,dc=com',
      {'name': [b'I\xc3\xa9losubmarine'], 'tokenGroups': [f'token<{i}>' for i in range(5)]})],
     [f'token<{i}>' for i in range(5)]),
    ('cn=ielosubmarine,OU=Users,dc=example,dc=com',
     [(None, {'cn': ['Configuration']}),
      ('cn=ielosubmarine,OU=Users,dc=example,dc=com', {'name': [b'I\xc3\xa9losubmarine']})], []),
    ('cn=ielosubmarine,OU=Users,dc=example,dc=com',
     [(None, {'cn': ['Configuration']}),
      ('cn=ielosubmarine,OU=Users,dc=example,dc=com', {'tokenGroups': [f'token<{i}>' for i in range(5)]})],
     [f'token<{i}>' for i in range(5)]),
    ('cn=ielosubmarine,OU=Users,dc=example,dc=com',
     [(None, {'cn': ['Configuration']}),
      ('cn=ielosubmarine,OU=Users,dc=example,dc=com',
      {'name': [b'I\xc3\xa9losubmarine'], 'tokenGroups': [f'token<{i}>' for i in range(5)]})],
     [f'token<{i}>' for i in range(5)]),
    ('cn=ielosubmarine,OU=Users,dc=example,dc=com',
     [(None, {'cn': ['Configuration']})],
     []),
))
def test_get_token_groups_from_user_dn(mocker, user_dn, mock_data, expected):
    settings = {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'cert_file': ' /etc/ssl/certs/ca-certificates.crt',
        'starttls': True,
        'timeout': 10,
    }

    ldap_search = MagicMock(return_value=mock_data)
    ldap_conn = MagicMock(search_ext_s=ldap_search)
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject', return_value=ldap_conn)
    with ldap_context(settings):
        assert get_token_groups_from_user_dn(user_dn) == expected
        # Token-Groups must be retrieved from a base scope query
        ldap_search.assert_called_once_with(user_dn, SCOPE_BASE, sizelimit=1, timeout=settings['timeout'],
                                            attrlist=['tokenGroups'])
