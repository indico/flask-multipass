# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import absolute_import, unicode_literals

from collections import namedtuple
from contextlib import contextmanager
from warnings import warn

import ldap
from flask import appcontext_tearing_down, current_app, g, has_app_context
from ldap.controls import SimplePagedResultsControl
from ldap.filter import escape_filter_chars
from ldap.ldapobject import ReconnectLDAPObject
from werkzeug.urls import url_parse

from flask_multipass._compat import PY2, iteritems, itervalues, text_type
from flask_multipass.exceptions import MultipassException
from flask_multipass.providers.ldap.exceptions import LDAPServerError
from flask_multipass.providers.ldap.globals import _ldap_ctx_stack, current_ldap
from flask_multipass.util import convert_app_data


#: A context holding the LDAP connection and the LDAP provider settings.
LDAPContext = namedtuple('LDAPContext', ('connection', 'settings'))

conn_keys = {'uri', 'bind_dn', 'bind_password', 'tls', 'starttls'}


@appcontext_tearing_down.connect
def _clear_ldap_cache(*args, **kwargs):
    if not has_app_context() or '_multipass_ldap_connections' not in g:
        return
    for conn in itervalues(g._multipass_ldap_connections):
        try:
            conn.unbind_s()
        except ldap.LDAPError:
            # That's ugly but we couldn't care less about a failure while disconnecting
            pass
    del g._multipass_ldap_connections


def _get_ldap_cache():
    """Returns the cache dictionary for ldap contexts"""
    if not has_app_context():
        return {}
    try:
        return g._multipass_ldap_connections
    except AttributeError:
        g._multipass_ldap_connections = cache = {}
        return cache


@contextmanager
def ldap_context(settings, use_cache=True):
    """Establishes an LDAP session context.

    Establishes a connection to the LDAP server from the `uri` in the
    ``settings`` and makes the context available in ``current_ldap``.

    Yields a namedtuple containing the connection to the server and the
    provider settings.

    :param settings: dict -- The settings for a LDAP provider.
    :param use_cache: bool -- If the connection should be cached.
    """
    try:
        connection = ldap_connect(settings, use_cache=use_cache)
        ldap_ctx = LDAPContext(connection=connection, settings=settings)
        _ldap_ctx_stack.push(ldap_ctx)
        try:
            yield ldap_ctx
        except ldap.LDAPError:
            # If something went wrong we get rid of cached connections.
            # This is mostly for the python shell where you have a very
            # long-living application context that usually results in
            # the ldap connection timing out.
            _clear_ldap_cache()
            raise
        finally:
            assert _ldap_ctx_stack.pop() is ldap_ctx, "Popped wrong LDAP context"
    except ldap.SERVER_DOWN:
        if has_app_context() and current_app.debug:
            raise
        raise MultipassException("The LDAP server is unreachable")
    except ldap.INVALID_CREDENTIALS:
        if has_app_context() and current_app.debug:
            raise
        raise ValueError("Invalid bind credentials")
    except ldap.SIZELIMIT_EXCEEDED:
        raise MultipassException("Size limit exceeded (try setting a smaller page size)")
    except ldap.TIMELIMIT_EXCEEDED:
        raise MultipassException("The time limit for the operation has been exceeded.")
    except ldap.TIMEOUT:
        raise MultipassException("The operation timed out.")
    except ldap.FILTER_ERROR:
        raise ValueError("The filter supplied to the operation is invalid. "
                         "(This is most likely due to a bad user or group filter.")


def ldap_connect(settings, use_cache=True):
    """Establishes an LDAP connection.

    Establishes a connection to the LDAP server from the `uri` in the
    ``settings``.

    To establish a connection, the settings must be specified:
     - ``uri``: valid URI which points to a LDAP server,
     - ``bind_dn``: `dn` used to initially bind every LDAP connection
     - ``bind_password``" password used for the initial bind
     - ``tls``: ``True`` if the connection should use TLS encryption
     - ``starttls``: ``True`` to negotiate TLS with the server

    `Note`: ``starttls`` is ignored if the URI uses LDAPS and ``tls`` is
    set to ``True``.

    This function re-uses an existing LDAP connection if there is one
    available in the application context, unless caching is disabled.

    :param settings: dict -- The settings for a LDAP provider.
    :param use_cache: bool -- If the connection should be cached.
    :return: The ldap connection.
    """

    if use_cache:
        cache = _get_ldap_cache()
        cache_key = frozenset((k, hash(v)) for k, v in iteritems(settings) if k in conn_keys)
        conn = cache.get(cache_key)
        if conn is not None:
            return conn

    uri_info = url_parse(settings['uri'])
    use_ldaps = uri_info.scheme == 'ldaps'
    credentials = (settings['bind_dn'], settings['bind_password'])
    ldap_connection = ReconnectLDAPObject(settings['uri'], bytes_mode=False)
    ldap_connection.protocol_version = ldap.VERSION3
    ldap_connection.set_option(ldap.OPT_REFERRALS, 0)
    ldap_connection.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND if use_ldaps else ldap.OPT_X_TLS_NEVER)
    if settings['verify_cert'] and settings['cert_file']:
        ldap_connection.set_option(ldap.OPT_X_TLS_CACERTFILE, settings['cert_file'])
    ldap_connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,
                               ldap.OPT_X_TLS_DEMAND if settings['verify_cert'] else ldap.OPT_X_TLS_ALLOW)
    # force the creation of a new TLS context. This must be the last TLS option.
    # see: http://stackoverflow.com/a/27713355/298479
    ldap_connection.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    if use_ldaps and settings['starttls']:
        warn("Unable to start TLS, LDAP connection already secured over SSL (LDAPS)")
    elif settings['starttls']:
        ldap_connection.start_tls_s()
    # TODO: allow anonymous bind
    ldap_connection.simple_bind_s(*credentials)
    if use_cache:
        cache[cache_key] = ldap_connection
    return ldap_connection


def find_one(base_dn, search_filter, attributes=None):
    """Looks for a single entry in the LDAP server.

    This will return the first entry given by the server which matches
    the ``search_filter`` found in the ``base_dn`` sub tree. If the
    ``search_filter`` matches multiples entries there is no guarantee
    the same entry is returned.

    :param base_dn: str -- The base DN from which to start the search.
    :param search_filter: str -- Representation of the filter to locate
                          the entry.
    :param attributes: list -- Attributes to be retrieved for the entry.
                       If ``None``, all attributes will be retrieved.
    :return: A tuple containing the `dn` of the entry as ``str`` and the
             found attributes in a ``dict``.
    """
    entry = current_ldap.connection.search_ext_s(base_dn, ldap.SCOPE_SUBTREE,
                                                 attrlist=attributes, filterstr=search_filter,
                                                 timeout=current_ldap.settings['timeout'], sizelimit=1)
    return next(((dn, data) for dn, data in entry if dn), (None, None))


def _build_assert_template(value, exact):
    assert_template = '(%s=%s)' if exact else '(%s=*%s*)'
    if len(value) == 1:
        return assert_template
    else:
        return '(|{})'.format(assert_template * len(value))


def _escape_filter_chars(value):
    if isinstance(value, text_type):
        return escape_filter_chars(value)
    elif PY2:
        return ''.join('\\%02x' % ord(c) for c in value)
    else:
        return ''.join('\\%02x' % c for c in value)


def _filter_format(filter_template, assertion_values):
    # like python-ldap's filter_format, but handles binary data (bytes) gracefully by escaping
    # everything so things don't break when searching e.g. for someone's binary objectSid
    return filter_template % tuple(_escape_filter_chars(v) for v in assertion_values)


def build_search_filter(criteria, type_filter, mapping=None, exact=False):
    """Builds a valid LDAP search filter for retrieving entries.

    :param criteria: dict -- Criteria to be ANDed together to build the
                     filter, if a criterion has many values they will
                     be ORed together.
    :param mapping: dict -- Mapping from criteria to LDAP attributes
    :param exact: bool -- Match attributes values exactly if ``True``,
                  othewise perform substring matching.
    :return: str -- Valid LDAP search filter.
    """

    assertions = convert_app_data(criteria, mapping or {})
    assert_templates = [_build_assert_template(value, exact) for _, value in iteritems(assertions)]
    assertions = [(k, v) for k, values in iteritems(assertions) if k and values for v in values]
    if not assertions:
        return None
    filter_template = '(&{}{})'.format("".join(assert_templates), type_filter)
    return _filter_format(filter_template, (item for assertion in assertions for item in assertion))


def get_page_cookie(server_ctrls):
    """Get the page control cookie from the server control list.

    :param server_ctrls: list -- Server controls including page control.
    :return: Cookie for page control or ``None`` if last page reached.
    :raises LDAPServerError: If the server doesn't support paging of
                             search results.
    """
    page_ctrls = [ctrl for ctrl in server_ctrls if ctrl.controlType == SimplePagedResultsControl.controlType]
    if not page_ctrls:
        raise LDAPServerError("The LDAP server ignores the RFC 2696 specification")
    return page_ctrls[0].cookie


def to_unicode(data):
    if isinstance(data, bytes):
        return data.decode('utf-8', 'replace')
    elif isinstance(data, dict):
        return {to_unicode(k): to_unicode(v) for k, v in iteritems(data)}
    elif isinstance(data, list):
        return [to_unicode(x) for x in data]
    elif isinstance(data, set):
        return {to_unicode(x) for x in data}
    elif isinstance(data, tuple):
        return tuple(to_unicode(x) for x in data)
    else:
        return data
