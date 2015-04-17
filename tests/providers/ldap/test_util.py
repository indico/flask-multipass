# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import pytest
from mock import call, MagicMock
from urlparse import urlparse

import ldap

from flask_multiauth.exceptions import MultiAuthException
from flask_multiauth.providers.ldap.globals import current_ldap
from flask_multiauth.providers.ldap.util import build_search_filter, find_one, ldap_context, to_unicode, LDAPContext


@pytest.mark.parametrize(('criteria', 'type_filter', 'mapping', 'exact', 'expected'), (
    ({}, '', None, True, None),
    ({}, '', '(|(objectClass=Person)(objectCategory=user))', True, None),
    ({'givenName': 'Alain', 'sn': "D'Issoir"}, '', None, True, "(&(givenName=Alain)(sn=D'Issoir))"),
    ({'givenName': 'Alain', 'last_name': "D'Issoir"}, '', {'last_name': 'sn'}, True,
     "(&(givenName=Alain)(sn=D'Issoir))"),
    ({'first_name': 'Alain', 'last_name': "D'Issoir"}, '', {'first_name': 'givenName', 'last_name': 'sn'}, True,
     "(&(givenName=Alain)(sn=D'Issoir))"),
    ({'first_name': 'Alain', 'last_name': "D'Issoir"}, '(|(objectClass=Person)(objectCategory=user))',
     {'first_name': 'givenName', 'last_name': 'sn'}, True,
     "(&(givenName=Alain)(sn=D'Issoir)(|(objectClass=Person)(objectCategory=user)))"),
    ({}, '', None, False, None),
    ({}, '', '(|(objectClass=Person)(objectCategory=user))', False, None),
    ({'givenName': 'Alain', 'sn': "D'Issoir"}, '', None, False, "(&(givenName=*Alain*)(sn=*D'Issoir*))"),
    ({'givenName': 'Alain', 'last_name': "D'Issoir"}, '', {'last_name': 'sn'}, False,
     "(&(givenName=*Alain*)(sn=*D'Issoir*))"),
    ({'first_name': 'Alain', 'last_name': "D'Issoir"}, '', {'first_name': 'givenName', 'last_name': 'sn'}, False,
     "(&(givenName=*Alain*)(sn=*D'Issoir*))"),
    ({'first_name': 'Alain', 'last_name': "D'Issoir"}, '(|(objectClass=Person)(objectCategory=user))',
     {'first_name': 'givenName', 'last_name': 'sn'}, False,
     "(&(givenName=*Alain*)(sn=*D'Issoir*)(|(objectClass=Person)(objectCategory=user)))")
))
def test_build_search_filter(criteria, type_filter, mapping, exact, expected):
    assert build_search_filter(criteria, type_filter, mapping, exact) == expected


@pytest.mark.parametrize(('data', 'expected'), (
    ({'uid': [b'amazzing'], 'givenName': [b'Antonio'], 'sn': [b'Mazzinghy']},
     {'uid': [u'amazzing'], 'givenName': [u'Antonio'], 'sn': [u'Mazzinghy']}),
    ({'uid': ['poisson'], 'company': [b'Chez Ordralfab\xc3\xa9tix'], 'sn': [b'I\xc3\xa9losubmarine']},
     {'uid': [u'poisson'], 'company': [u'Chez Ordralfab\xe9tix'], 'sn': [u'I\xe9losubmarine']})
))
def test_to_unicode(data, expected):
    assert to_unicode(data) == expected


@pytest.mark.parametrize(('settings', 'options'), (
    ({'uri': 'ldaps://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'tls': True,
      'starttls': True},
     ((ldap.OPT_REFERRALS, 0), (ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND))),
    ({'uri': 'ldaps://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'tls': False,
      'starttls': True},
     ((ldap.OPT_REFERRALS, 0), (ldap.OPT_X_TLS, ldap.OPT_X_TLS_NEVER))),
    ({'uri': 'ldaps://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'tls': True,
      'starttls': False},
     ((ldap.OPT_REFERRALS, 0), (ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND))),
    ({'uri': 'ldaps://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'tls': False,
      'starttls': False},
     ((ldap.OPT_REFERRALS, 0), (ldap.OPT_X_TLS, ldap.OPT_X_TLS_NEVER))),
    ({'uri': 'ldap://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'tls': True,
      'starttls': True},
     ((ldap.OPT_REFERRALS, 0), (ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND))),
    ({'uri': 'ldap://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'tls': False,
      'starttls': True},
     ((ldap.OPT_REFERRALS, 0), (ldap.OPT_X_TLS, ldap.OPT_X_TLS_NEVER))),
    ({'uri': 'ldap://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'tls': True,
      'starttls': False},
     ((ldap.OPT_REFERRALS, 0), (ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND))),
    ({'uri': 'ldap://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'tls': False,
      'starttls': False},
     ((ldap.OPT_REFERRALS, 0), (ldap.OPT_X_TLS, ldap.OPT_X_TLS_NEVER))),
))
def test_ldap_context(mocker, settings, options):
    warn = mocker.patch('flask_multiauth.providers.ldap.util.warn')
    ldap_initialize = mocker.patch('flask_multiauth.providers.ldap.util.ldap.initialize')
    ldap_conn = MagicMock()
    ldap_initialize.return_value = ldap_conn
    with ldap_context(settings) as ldap_ctx:
        ldap_initialize.called_once_with(settings['uri'])
        assert ldap_conn.protocol_version == ldap.VERSION3, 'LDAP v3 has not been set'
        assert ldap_conn.set_option.mock_calls == [call.set_option(*args) for args in options], 'Not all options set'
        if settings['starttls']:
            if urlparse(settings['uri']).scheme == 'ldaps':
                warn.assert_called_once_with('Unable to start TLS, LDAP connection already secured over SSL (LDAPS)')
            else:
                ldap_conn.start_tls_s.assert_called_once()
        ldap_conn.simple_bind_s.assert_called_once_with(settings['bind_dn'], settings['bind_password'])
        assert current_ldap == ldap_ctx, 'The LDAP context has not been set as the current one'
        assert current_ldap == LDAPContext(connection=ldap_conn, settings=settings)
    ldap_conn.unbind_s.called_once()
    assert not current_ldap, 'The LDAP context has not been unset'


@pytest.mark.parametrize(('method', 'triggered_exception', 'caught_exception', 'message'), (
    ('search_s', ldap.SERVER_DOWN, MultiAuthException, 'The LDAP server is unreachable'),
    ('simple_bind_s', ldap.INVALID_CREDENTIALS, ValueError, 'Invalid bind credentials'),
    ('simple_bind_s', ldap.SIZELIMIT_EXCEEDED, MultiAuthException,
     'Size limit exceeded (try setting a smaller page size)'),
    ('simple_bind_s', ldap.TIMELIMIT_EXCEEDED, MultiAuthException,
     'The time limit for the operation has been exceeded.'),
    ('simple_bind_s', ldap.TIMEOUT, MultiAuthException, 'The operation timed out.'),
    ('simple_bind_s', ldap.FILTER_ERROR, ValueError,
     'The filter supplied to the operation is invalid. (This is most likely due to a base user or group filter.'),
))
def test_ldap_context_invalid_credentials(mocker, method, triggered_exception, caught_exception, message):
    settings = {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'tls': True,
        'starttls': True
    }

    ldap_initialize = mocker.patch('flask_multiauth.providers.ldap.util.ldap.initialize')
    ldap_conn = MagicMock()
    getattr(ldap_conn, method).side_effect = triggered_exception
    ldap_initialize.return_value = ldap_conn

    with pytest.raises(caught_exception) as excinfo:
        with ldap_context(settings):
            current_ldap.connection.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE)
    assert excinfo.value.message == message


@pytest.mark.parametrize(('base_dn', 'search_filter', 'data', 'expected'), (
    ('dc=example,dc=com', '(&(mail=alain.dissoir@mail.com)(objectCategory=user))',
     [('cn=alaindi,OU=Users,dc=example,dc=com', {'mail': ['alain.dissoir@mail.com'], 'name': ["Alain D'issoir"]})],
     ('cn=alaindi,OU=Users,dc=example,dc=com', {'mail': ['alain.dissoir@mail.com'], 'name': ["Alain D'issoir"]})),
    ('dc=example,dc=com', '(&(mail=alain.dissoir@mail.com)(objectCategory=user))',
     [(None, {'cn': ['Configuration']}),
      ('cn=alaindi,OU=Users,dc=example,dc=com', {'mail': ['alain.dissoir@mail.com'], 'name': ["Alain D'issoir"]})],
     ('cn=alaindi,OU=Users,dc=example,dc=com', {'mail': ['alain.dissoir@mail.com'], 'name': ["Alain D'issoir"]})),
    ('dc=example,dc=com', '(&(mail=alain.dissoir@mail.com)(objectCategory=user))',
     [(None, {'cn': ['Configuration']})], (None, None)),
    ('dc=example,dc=com', '(&(mail=alain.dissoir@mail.com)(objectCategory=user))',
     [(None, None), (None, {'cn': ['Configuration']})], (None, None))
))
def test_find_one(mocker, base_dn, search_filter, data, expected):
    settings = {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'tls': True,
        'starttls': True,
        'timeout': 10
    }

    ldap_search = MagicMock(return_value=data)
    ldap_conn = MagicMock(search_ext_s=ldap_search)
    mocker.patch('flask_multiauth.providers.ldap.util.ldap.initialize', return_value=ldap_conn)

    with ldap_context(settings):
        assert find_one(base_dn, search_filter) == expected
