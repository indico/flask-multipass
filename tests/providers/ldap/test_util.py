# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from collections import OrderedDict
from unittest.mock import MagicMock, call
from urllib.parse import urlsplit

import ldap
import pytest

from flask_multipass.exceptions import MultipassException
from flask_multipass.providers.ldap.globals import current_ldap
from flask_multipass.providers.ldap.util import LDAPContext, build_search_filter, find_one, ldap_context, to_unicode
from flask_multipass.util import convert_app_data


@pytest.mark.parametrize(('criteria', 'type_filter', 'mapping', 'exact', 'expected'), (
    ({}, '', None, True, None),
    ({}, '', '(|(objectClass=Person)(objectCategory=user))', True, None),
    ({'cn': ['foobar'], 'objectSid': [b'\00\xa0foo']}, '', None, True, r'(&(cn=foobar)(objectSid=\00\a0\66\6f\6f))'),
    ({'givenName': ['Alain'], 'sn': ["D'Issoir"]}, '', None, True, "(&(givenName=Alain)(sn=D'Issoir))"),
    ({'givenName': ['Alain'], 'last_name': ["D'Issoir"]}, '', {'last_name': 'sn'}, True,
     "(&(givenName=Alain)(sn=D'Issoir))"),
    ({'first_name': ['Alain'], 'last_name': ["D'Issoir"]}, '', {'first_name': 'givenName', 'last_name': 'sn'}, True,
     "(&(givenName=Alain)(sn=D'Issoir))"),
    ({'first_name': ['Alain'], 'last_name': ["D'Issoir"]}, '(|(objectClass=Person)(objectCategory=user))',
     {'first_name': 'givenName', 'last_name': 'sn'}, True,
     "(&(givenName=Alain)(sn=D'Issoir)(|(objectClass=Person)(objectCategory=user)))"),
    ({}, '', None, False, None),
    ({}, '', '(|(objectClass=Person)(objectCategory=user))', False, None),
    ({'givenName': ['Alain'], 'sn': ["D'Issoir"]}, '', None, False, "(&(givenName=*Alain*)(sn=*D'Issoir*))"),
    ({'givenName': ['Alain'], 'last_name': ["D'Issoir"]}, '', {'last_name': 'sn'}, False,
     "(&(givenName=*Alain*)(sn=*D'Issoir*))"),
    ({'first_name': ['Alain'], 'last_name': ["D'Issoir"]}, '', {'first_name': 'givenName', 'last_name': 'sn'}, False,
     "(&(givenName=*Alain*)(sn=*D'Issoir*))"),
    ({'first_name': ['Alain'], 'last_name': ["D'Issoir"]}, '(|(objectClass=Person)(objectCategory=user))',
     {'first_name': 'givenName', 'last_name': 'sn'}, False,
     "(&(givenName=*Alain*)(sn=*D'Issoir*)(|(objectClass=Person)(objectCategory=user)))"),
    ({'email': ['alaindissoir@mail.com']}, '(|(objectClass=Person)(objectCategory=user))', {'email': 'mail'}, False,
     '(&(mail=*alaindissoir@mail.com*)(|(objectClass=Person)(objectCategory=user)))'),
    ({'email': ['alaindissoir@mail.com']}, '(|(objectClass=Person)(objectCategory=user))', {'email': 'mail'}, True,
     '(&(mail=alaindissoir@mail.com)(|(objectClass=Person)(objectCategory=user)))'),
    ({'email': ['alaindissoir@mail.com', 'alain@dissoir.com', 'alaindi@mail.com']},
     '(|(objectClass=Person)(objectCategory=user))', {'email': 'mail'}, False,
     '(&(|(mail=*alaindissoir@mail.com*)(mail=*alain@dissoir.com*)(mail=*alaindi@mail.com*))'
     '(|(objectClass=Person)(objectCategory=user)))'),
    ({'email': ['alaindissoir@mail.com', 'alain@dissoir.com', 'alaindi@mail.com']},
     '(|(objectClass=Person)(objectCategory=user))', {'email': 'mail'}, True,
     '(&(|(mail=alaindissoir@mail.com)(mail=alain@dissoir.com)(mail=alaindi@mail.com))'
     '(|(objectClass=Person)(objectCategory=user)))'),
))
def test_build_search_filter(monkeypatch, criteria, type_filter, mapping, exact, expected):
    def _convert_app_data(*args, **kwargs):
        return OrderedDict(sorted(convert_app_data(*args, **kwargs).items()))
    monkeypatch.setattr('flask_multipass.providers.ldap.util.convert_app_data', _convert_app_data)
    assert build_search_filter(criteria, type_filter, mapping, exact) == expected


@pytest.mark.parametrize(('data', 'expected'), (
    ({'uid': [b'amazzing'], 'givenName': [b'Antonio'], 'sn': [b'Mazzinghy']},
     {'uid': ['amazzing'], 'givenName': ['Antonio'], 'sn': ['Mazzinghy']}),
    ({'uid': ['poisson'], 'company': [b'Chez Ordralfab\xc3\xa9tix'], 'sn': [b'I\xc3\xa9losubmarine']},
     {'uid': ['poisson'], 'company': ['Chez Ordralfab\xe9tix'], 'sn': ['I\xe9losubmarine']}),
))
def test_to_unicode(data, expected):
    assert to_unicode(data) == expected


@pytest.mark.parametrize(('settings', 'options'), (
    ({'uri': 'ldaps://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'verify_cert': True,
      'cert_file': '/etc/ssl/certs/ca-certificates.crt',
      'starttls': True},
     ((ldap.OPT_REFERRALS, 0),
      (ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt'),
      (ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND), (ldap.OPT_X_TLS_NEWCTX, 0))),
    ({'uri': 'ldaps://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'verify_cert': False,
      'cert_file': '/etc/ssl/certs/ca-certificates.crt',
      'starttls': True},
     ((ldap.OPT_REFERRALS, 0),
      (ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW), (ldap.OPT_X_TLS_NEWCTX, 0))),
    ({'uri': 'ldaps://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'verify_cert': True,
      'cert_file': '/etc/ssl/certs/ca-certificates.crt',
      'starttls': False},
     ((ldap.OPT_REFERRALS, 0),
      (ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt'),
      (ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND), (ldap.OPT_X_TLS_NEWCTX, 0))),
    ({'uri': 'ldaps://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'verify_cert': False,
      'starttls': False},
     ((ldap.OPT_REFERRALS, 0),
      (ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW), (ldap.OPT_X_TLS_NEWCTX, 0))),
    ({'uri': 'ldap://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'verify_cert': True,
      'cert_file': '/etc/ssl/certs/ca-certificates.crt',
      'starttls': True},
     ((ldap.OPT_REFERRALS, 0),
      (ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt'),
      (ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND), (ldap.OPT_X_TLS_NEWCTX, 0))),
    ({'uri': 'ldap://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'verify_cert': False,
      'cert_file': '/etc/ssl/certs/ca-certificates.crt',
      'starttls': True},
     ((ldap.OPT_REFERRALS, 0),
      (ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW), (ldap.OPT_X_TLS_NEWCTX, 0))),
    ({'uri': 'ldap://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'verify_cert': True,
      'cert_file': '/etc/ssl/certs/ca-certificates.crt',
      'starttls': False},
     ((ldap.OPT_REFERRALS, 0),
      (ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt'),
      (ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND), (ldap.OPT_X_TLS_NEWCTX, 0))),
    ({'uri': 'ldap://ldap.example.com:636',
      'bind_dn': 'uid=admin,DC=example,DC=com',
      'bind_password': 'LemotdepassedeLDAP',
      'verify_cert': False,
      'starttls': False},
     ((ldap.OPT_REFERRALS, 0),
      (ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW), (ldap.OPT_X_TLS_NEWCTX, 0))),
))
def test_ldap_context(mocker, settings, options):
    warn = mocker.patch('flask_multipass.providers.ldap.util.warn')
    ldap_initialize = mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject')
    ldap_conn = MagicMock()
    ldap_initialize.return_value = ldap_conn
    with ldap_context(settings) as ldap_ctx:
        ldap_initialize.assert_called_once_with(settings['uri'], bytes_mode=False)
        assert ldap_conn.protocol_version == ldap.VERSION3, 'LDAP v3 has not been set'
        assert ldap_conn.set_option.mock_calls == [call.set_option(*args) for args in options], 'Not all options set'
        if settings['starttls']:
            if urlsplit(settings['uri']).scheme == 'ldaps':
                warn.assert_called_once_with('Unable to start TLS, LDAP connection already secured over SSL (LDAPS)',
                                             stacklevel=1)
            else:
                ldap_conn.start_tls_s.assert_called_once_with()
        ldap_conn.simple_bind_s.assert_called_once_with(settings['bind_dn'], settings['bind_password'])
        assert current_ldap == ldap_ctx, 'The LDAP context has not been set as the current one'
        assert current_ldap == LDAPContext(connection=ldap_conn, settings=settings)
    assert not current_ldap, 'The LDAP context has not been unset'


@pytest.mark.parametrize(('method', 'triggered_exception', 'caught_exception', 'message'), (
    ('search_s', ldap.SERVER_DOWN, MultipassException, 'The LDAP server is unreachable'),
    ('simple_bind_s', ldap.INVALID_CREDENTIALS, ValueError, 'Invalid bind credentials'),
    ('simple_bind_s', ldap.SIZELIMIT_EXCEEDED, MultipassException,
     'Size limit exceeded (try setting a smaller page size)'),
    ('simple_bind_s', ldap.TIMELIMIT_EXCEEDED, MultipassException,
     'The time limit for the operation has been exceeded.'),
    ('simple_bind_s', ldap.TIMEOUT, MultipassException, 'The operation timed out.'),
    ('simple_bind_s', ldap.FILTER_ERROR, ValueError,
     'The filter supplied to the operation is invalid. (This is most likely due to a bad user or group filter.'),
))
def test_ldap_context_invalid_credentials(mocker, method, triggered_exception, caught_exception, message):
    settings = {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'cert_file': '/etc/ssl/certs/ca-certificates.crt',
        'starttls': True,
    }

    ldap_initialize = mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject')
    ldap_conn = MagicMock()
    getattr(ldap_conn, method).side_effect = triggered_exception
    ldap_initialize.return_value = ldap_conn

    with pytest.raises(caught_exception) as excinfo:
        with ldap_context(settings):
            current_ldap.connection.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE)
    assert str(excinfo.value) == message


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
     [(None, None), (None, {'cn': ['Configuration']})], (None, None)),
))
def test_find_one(mocker, base_dn, search_filter, data, expected):
    settings = {
        'uri': 'ldaps://ldap.example.com:636',
        'bind_dn': 'uid=admin,DC=example,DC=com',
        'bind_password': 'LemotdepassedeLDAP',
        'verify_cert': True,
        'cert_file': '/etc/ssl/certs/ca-certificates.crt',
        'starttls': True,
        'timeout': 10,
    }

    ldap_search = MagicMock(return_value=data)
    ldap_conn = MagicMock(search_ext_s=ldap_search)
    mocker.patch('flask_multipass.providers.ldap.util.ReconnectLDAPObject', return_value=ldap_conn)

    with ldap_context(settings):
        assert find_one(base_dn, search_filter) == expected
