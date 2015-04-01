from collections import namedtuple
from contextlib import contextmanager
from urlparse import urlparse
from warnings import warn

import ldap
from ldap.controls import SimplePagedResultsControl

from flask_multiauth._compat import iteritems
from flask_multiauth.providers.ldap.exceptions import LDAPServerError
from flask_multiauth.providers.ldap.globals import _ldap_ctx_stack, current_ldap
from flask_multiauth.util import map_app_data

#: A context holding the LDAP connection and the LDAP provider settings.
LDAPContext = namedtuple('LDAPContext', ('connection', 'settings'))


@contextmanager
def ldap_context(settings):
    """Establishes an LDAP session context.

    Establishes a connection to the LDAP server from the `uri` in the
    ``settings`` and makes the context available in ``current_ldap``.

    TODO explain settings used for establishing connection

    :param settings: dict -- The settings for a LDAP provider.
    :return: LDAPContext -- A ``namedtuple`` tuple containing the
             connection to the server and the provider settings.
    """
    uri_info = urlparse(settings['uri'])
    credentials = (settings['bind_dn'], settings['bind_password'])
    ldap_ctx = LDAPContext(conn=None, settings=settings)
    try:
        ldap_ctx.connection = ldap.initialize(settings['uri'])
        ldap_ctx.connection.protocol_version = ldap.VERSION3
        ldap_ctx.connection.set_option(ldap.OPT_REFERRALS, 0)
        ldap_ctx.connection.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND
                                       if settings['tls'] else ldap.OPT_X_TLS_NEVER)
        if uri_info.scheme != 'ldaps' and settings['starttls']:
            ldap_ctx.connection.start_tls_s()
        elif settings['starttls']:
            warn("Unable to start TLS, LDAP connection already secured over SSL (LDAPS)")
        # TODO: allow annonyous bind
        ldap_ctx.connection.simple_bind_s(*credentials)
        _ldap_ctx_stack.push(ldap_ctx)
        yield ldap_ctx
    except ldap.INVALID_CREDENTIALS:
        raise ValueError("Invalid bind credentials")
    except ldap.SIZELIMIT_EXCEEDED:
        raise ValueError("Size limit exceeded (try setting a smaller page size)")
    finally:
        ldap_ctx.connection.unbind_s()
        assert _ldap_ctx_stack.pop() is ldap_ctx, "Popped wrong LDAP context"


def find_one(base_dn, search_filter, attributes=None):
    """Looks for a single entry in the LDAP server.

    This will return the first entry given by the server which matches
    the ``search_filter`` found in the ``base_dn`` subtree. If the
    ``search_filter`` matches multiples entries there is no guarantee
    the same entry is returned.

    :param base_dn: str -- The base DN from which to start the search.
    :param search_filter: str -- Representation of the filter to locate
                          the entry.
    :param attributes: list -- Attributes to be retrieved for the entry.
                       If ``None``, all attributes will be retrieved.
    :return: A tuple containint the `dn` of the entry as ``str`` and the
             found attributes in a ``dict``.
    """
    entry = current_ldap.connection.search_ext_s(base_dn, ldap.SCOPE_SUBTREE,
                                                 attrlist=attributes, filterstr=search_filter,
                                                 timeout=current_ldap.settings['timeout'], sizelimit=1)
    return next(((dn, data) for dn, data in entry if dn), (None, None))


def build_search_filter(criteria, type_filter, mapping=None, exact=False):
    """Builds a valid LDAP search filter for retrieving entries.

    :param criteria: dict -- Criteria to be `AND`ed together to build
                     the filter.
    :param mapping: dict -- Mapping from criteria to LDAP attributes
    :param exact: bool -- Match attributes values exactly if ``True``,
                  othewise perform substring matching.
    :return: str -- Valid LDAP search filter.
    """
    assertions = map_app_data(criteria, mapping or {})
    if not assertions:
        return None
    assertions = (item for assertion in iteritems(assertions) for item in assertion)
    assert_template = '(%s=%s)' if exact else '(%s=*%s*)'
    filter_template = '(&{}{})'.format(assert_template * len(assertions), type_filter)
    return ldap.filter.filter_format(filter_template, assertions)


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
