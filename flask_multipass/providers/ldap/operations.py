# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import absolute_import, unicode_literals

from ldap import NO_SUCH_OBJECT, SCOPE_BASE, SCOPE_SUBTREE
from ldap.controls import SimplePagedResultsControl

from flask_multipass.exceptions import GroupRetrievalFailed, IdentityRetrievalFailed
from flask_multipass.providers.ldap.globals import current_ldap
from flask_multipass.providers.ldap.util import build_search_filter, find_one, get_page_cookie


def build_user_search_filter(criteria, mapping=None, exact=False):  # pragma: no cover
    """Builds the LDAP search filter for retrieving users.

    :param criteria: dict -- Criteria to be `AND`ed together to build
                     the filter.
    :param mapping: dict -- Mapping from criteria to LDAP attributes
    :param exact: bool -- Match attributes values exactly if ``True``,
                  othewise perform substring matching.
    :return: str -- Valid LDAP search filter.
    """
    type_filter = current_ldap.settings['user_filter']
    return build_search_filter(criteria, type_filter, mapping, exact)


def build_group_search_filter(criteria, mapping=None, exact=False):  # pragma: no cover
    """Builds the LDAP search filter for retrieving groups.

    :param criteria: dict -- Criteria to be `AND`ed together to build
                     the filter.
    :param mapping: dict -- Mapping from criteria to LDAP attributes
    :param exact: bool -- Match attributes values exactly if ``True``,
                  othewise perform substring matching.
    :return: str -- Valid LDAP search filter.
    """
    type_filter = current_ldap.settings['group_filter']
    return build_search_filter(criteria, type_filter, mapping, exact)


def get_user_by_id(uid, attributes=None):
    """Retrieves a user's data from LDAP, given its identifier.

    :param uid: str -- the identifier of the user
    :param attributes: list -- Attributes to be retrieved for the user.
                       If ``None``, all attributes will be retrieved.
    :raises IdentityRetrievalFailed: If the identifier is falsely.
    :return: A tuple containing the `dn` of the user as ``str`` and the
             found attributes in a ``dict``.
    """
    if not uid:
        raise IdentityRetrievalFailed("No identifier specified")
    user_filter = build_user_search_filter({current_ldap.settings['uid']: {uid}}, exact=True)
    return find_one(current_ldap.settings['user_base'], user_filter, attributes=attributes)


def get_group_by_id(gid, attributes=None):
    """Retrieves a user's data from LDAP, given its identifier.

    :param gid: str -- the identifier of the group
    :param attributes: list -- Attributes to be retrieved for the group.
                       If ``None``, all attributes will be retrieved.
    :raises GroupRetrievalFailed: If the identifier is falsely.
    :return: A tuple containing the `dn` of the group as ``str`` and the
             found attributes in a ``dict``.
    """
    if not gid:
        raise GroupRetrievalFailed("No identifier specified")
    group_filter = build_group_search_filter({current_ldap.settings['gid']: {gid}}, exact=True)
    return find_one(current_ldap.settings['group_base'], group_filter, attributes=attributes)


def search(base_dn, search_filter, attributes):
    """Iterative LDAP search using page control.

    :param base_dn: str -- The base DN from which to start the search.
    :param search_filter: str -- Representation of the filter to apply
                          in the search.
    :param attributes: list -- Attributes to be retrieved for each
                       entry. If ``None``, all attributes will be
                       retrieved.
    :returns: A generator which yields one search result at a time as a
              tuple containing a `dn` as ``str`` and `attributes` as
              ``dict``.
    """
    connection, settings = current_ldap
    page_ctrl = SimplePagedResultsControl(True, size=settings['page_size'], cookie='')

    while True:
        msg_id = connection.search_ext(base_dn, SCOPE_SUBTREE, filterstr=search_filter, attrlist=attributes,
                                       serverctrls=[page_ctrl], timeout=settings['timeout'])
        try:
            _, r_data, __, server_ctrls = connection.result3(msg_id, timeout=settings['timeout'])
        except NO_SUCH_OBJECT:
            break

        for dn, entry in r_data:
            if dn:
                yield dn, entry

        page_ctrl.cookie = get_page_cookie(server_ctrls)
        if not page_ctrl.cookie:
            # End of results
            break


def get_token_groups_from_user_dn(user_dn):
    """Get the list of SIDs of nested groups the user is a member of.

    This is uses the Active Directory specific attribute `tokenGroups`,
    which is a list of security identifiers (SIDs) of groups (direct and
    nested) a user is a member of. This avoid a recursive lookup through
    the group memberships.
    To retrieve this attribute, a query on the user's DN using the base
    scope is required, hence the existence of this method instead of
    simply retrieving the attribute when looking for the user.

    :param user_dn: str -- DN of the user whose token groups list is
                    retrieved
    :returns: list -- the secure identifiers of groups the user is a
              member of.
    """
    entry = current_ldap.connection.search_ext_s(user_dn, SCOPE_BASE, attrlist=['tokenGroups'],
                                                 timeout=current_ldap.settings['timeout'], sizelimit=1)
    user_data = next((data for dn, data in entry if dn), None)
    if not user_data:
        return []
    return user_data.get('tokenGroups', [])
