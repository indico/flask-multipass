# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import pytest
from mock import MagicMock

from flask_multiauth.exceptions import GroupRetrievalFailed, IdentityRetrievalFailed
from flask_multiauth.providers.ldap.operations import get_group_by_id, get_user_by_id, search
from flask_multiauth.providers.ldap.util import ldap_context


def test_get_user_by_id_handles_none_id():
    with pytest.raises(IdentityRetrievalFailed) as excinfo:
        get_user_by_id(None)
    assert excinfo.value.message == 'No identifier specified'


def test_get_group_by_id_handles_none_id():
    with pytest.raises(GroupRetrievalFailed) as excinfo:
        get_group_by_id(None)
    assert excinfo.value.message == 'No identifier specified'


@pytest.mark.parametrize(('settings', 'base_dn', 'search_filter', 'attributes', 'mock_data', 'expected'), (
    ({'uri': 'ldaps://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'tls': True,
      'starttls': True,
      'timeout': 10,
      'page_size': 3},
     'dc=example,dc=com', '(&(name=Alain)(objectCategory=user))', ['mail'],
     {'msg_ids': ['msg_id<{}>'.format(i) for i in range(3)],
      'cookies': ['cookie<{}>'.format(i) for i in range(2)],
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
    mocker.patch('flask_multiauth.providers.ldap.operations.SimplePagedResultsControl', return_value=page_ctrl)
    ldap_connection = MagicMock(result3=MagicMock(side_effect=((None, entries, None, [page_ctrl])
                                                               for entries in mock_data['results'])),
                                search_ext=MagicMock(side_effect=mock_data['msg_ids']))
    mocker.patch('flask_multiauth.providers.ldap.util.ldap.initialize', return_value=ldap_connection)
    mocker.patch('flask_multiauth.providers.ldap.operations.get_page_cookie', side_effect=mock_data['cookies'])

    with ldap_context(settings):
        for i, result in enumerate(search(base_dn, search_filter, attributes)):
            assert result == expected[i]
