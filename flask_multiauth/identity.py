# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask import current_app

from flask_multiauth._compat import iteritems, add_metaclass
from flask_multiauth.util import SupportsMeta


@add_metaclass(SupportsMeta)
class IdentityProvider(object):
    """Provides the base for an identity provider.

    :param multiauth: The Flask-MultiAuth instancee
    :param name: The name of this identity provider instance
    :param settings: The settings dictionary for this identity
                     provider instance
    """

    __support_attrs__ = {'supports_refresh': 'refresh_identity',
                         'supports_search': 'search_identities',
                         'supports_groups': ('get_group', 'search_groups', 'group_class')}
    #: The entry point to lookup providers (do not override this!)
    _entry_point = 'flask_multiauth.identity_providers'
    #: If there may be multiple instances of this identity provider
    multi_instance = True
    #: If the provider supports refreshing identity information
    supports_refresh = False
    #: If the provider supports searching identities
    supports_search = False
    #: If the provider also provides groups and membership information
    supports_groups = False
    #: The class that represents groups from this provider. Must be a
    #: subclass of :class:`.Group`
    group_class = None

    def __init__(self, multiauth, name, settings):
        self.multiauth = multiauth
        self.name = name
        self.settings = settings.copy()
        self.settings.setdefault('identity_info_keys', current_app.config['MULTIAUTH_IDENTITY_INFO_KEYS'])
        self.settings.setdefault('mapping', {})
        self.title = self.settings.pop('title', self.name)
        search_enabled = self.settings.pop('search_enabled', self.supports_search)
        if search_enabled and not self.supports_search:
            raise ValueError('Provider does not support searching: ' + type(self).__name__)
        self.supports_search = search_enabled

    def get_identity_from_auth(self, auth_info):  # pragma: no cover
        """Retrieves identity information after authentication

        :param auth_info: An :class:`.AuthInfo` instance from an auth
                          provider
        :return: An :class:`.IdentityInfo` instance containing identity
                 information or ``None`` if no identity was found
        """
        raise NotImplementedError

    def refresh_identity(self, identifier, multiauth_data):  # pragma: no cover
        """Retrieves identity information for an existing user identity

        This method returns user information for an identity that has
        been retrieved before based on the provider-specific refresh
        data.

        :param identifier: The `identifier` from :class:`.IdentityInfo`
        :param multiauth_data: The `multiauth_data` dict from
                               :class:`.IdentityInfo`
        """
        if self.supports_refresh:
            raise NotImplementedError

    def search_identities(self, criteria, exact=False):  # pragma: no cover
        """Searches user identities matching certain criteria

        :param criteria: A dict containing the criteria to search for.
        :param exact: If criteria need to match exactly, i.e. no
                      substring matches are performed.
        :return: An iterable of matching identities.
        """
        if self.supports_search:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider does not support searching')

    def get_group(self, name):
        """Returns a specific group

        :param name: The name of the group
        :return: An instance of :attr:`group_class`
        """
        if self.supports_groups:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider does not provide groups')

    def search_groups(self, name, exact=False):
        """Searches groups by name

        :param name: The name to search for
        :param exact: If the name needs to match exactly, i.e. no
                      substring matches are performed
        :return: An iterable of matching :attr:`group_class` objects
        """
        if self.supports_groups:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider does not provide groups')

    def map_search_criteria(self, criteria):
        """Maps the search criteria from application keys to provider keys

        :param criteria: A dict containing search criteria
        :return: A dict containing search criteria with mapped keys
        """
        mapping = self.settings['mapping']
        return {mapping.get(key, key): value for key, value in iteritems(criteria)}

    def __repr__(self):
        return '<{}({})>'.format(type(self).__name__, self.name)
