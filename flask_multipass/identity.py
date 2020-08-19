# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask import current_app

from flask_multipass._compat import add_metaclass
from flask_multipass.util import SupportsMeta, convert_app_data


@add_metaclass(SupportsMeta)
class IdentityProvider(object):
    """Provides the base for an identity provider.

    :param multipass: The Flask-Multipass instance
    :param name: The name of this identity provider instance
    :param settings: The settings dictionary for this identity
                     provider instance
    """

    __support_attrs__ = {'supports_refresh': 'refresh_identity',
                         'supports_get': 'get_identity',
                         'supports_search': 'search_identities',
                         'supports_search_ex': 'search_identities_ex',
                         'supports_groups': ('get_group', 'search_groups', 'group_class'),
                         'supports_get_identity_groups': 'get_identity_groups'}
    #: The entry point to lookup providers (do not override this!)
    _entry_point = 'flask_multipass.identity_providers'
    #: If there may be multiple instances of this identity provider
    multi_instance = True
    #: If the provider supports refreshing identity information
    supports_refresh = False
    #: If the provider supports getting identity information based from
    #: an identifier
    supports_get = True
    #: If the provider supports searching identities
    supports_search = False
    #: If the provider supports the extended identity search feature
    supports_search_ex = False
    #: If the provider also provides groups and membership information
    supports_groups = False
    #: If the provider supports getting the list of groups an identity belongs to
    supports_get_identity_groups = False
    #: The class that represents groups from this provider. Must be a
    #: subclass of :class:`.Group`
    group_class = None

    def __init__(self, multipass, name, settings):
        self.multipass = multipass
        self.name = name
        self.settings = settings.copy()
        self.settings.setdefault('identity_info_keys', current_app.config['MULTIPASS_IDENTITY_INFO_KEYS'])
        self.settings.setdefault('mapping', {})
        self.title = self.settings.pop('title', self.name)
        search_enabled = self.settings.pop('search_enabled', self.supports_search)
        if search_enabled and not self.supports_search:
            raise ValueError('Provider does not support searching: ' + type(self).__name__)
        self.supports_search = search_enabled
        if not self.supports_search:
            self.supports_search_ex = False

    def get_identity_from_auth(self, auth_info):  # pragma: no cover
        """Retrieves identity information after authentication

        :param auth_info: An :class:`.AuthInfo` instance from an auth
                          provider
        :return: An :class:`.IdentityInfo` instance containing identity
                 information or ``None`` if no identity was found
        """
        raise NotImplementedError

    def refresh_identity(self, identifier, multipass_data):  # pragma: no cover
        """Retrieves identity information for an existing user identity

        This method returns identity information for an identity that
        has been retrieved before based on the provider-specific refresh
        data.

        :param identifier: The `identifier` from :class:`.IdentityInfo`
        :param multipass_data: The `multipass_data` dict from
                               :class:`.IdentityInfo`
        """
        if self.supports_refresh:
            raise NotImplementedError

    def get_identity(self, identifier):  # pragma: no cover
        """Retrieves identity information.

        This method is similar to :meth:`refresh_identity` but does
        not require `multiauth_data`

        :param identifier: The unique user identifier used by the
                           provider.
        :return: An :class:`.IdentityInfo` instance or ``None`` if the
                 identity does not exist.
        """
        if self.supports_get:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider does not support getting an identity based on the identifier')

    def get_identity_groups(self, identifier):  # pragma: no cover
        """Retrieves the list of groups a user identity belongs to

        :param identifier: The unique user identifier used by the
                           provider.
        :return: A set of groups
        """
        if self.supports_get_identity_groups:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider does not support getting the list of groups for an identity')

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

    def search_identities_ex(self, criteria, exact=False, limit=None):  # pragma: no cover
        """Search user identities matching certain criteria.

        :param criteria: A dict containing the criteria to search for.
        :param exact: If criteria need to match exactly, i.e. no
                      substring matches are performed.
        :param limit: The max number of identities to return.
        :return: A tuple containing ``(identities, total_count)``.
        """
        if self.supports_search_ex:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider does not support extended searching')

    def get_group(self, name):  # pragma: no cover
        """Returns a specific group

        :param name: The name of the group
        :return: An instance of :attr:`group_class`
        """
        if self.supports_groups:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider does not provide groups')

    def search_groups(self, name, exact=False):  # pragma: no cover
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
        return convert_app_data(criteria, mapping)

    def __repr__(self):
        return '<{}({})>'.format(type(self).__name__, self.name)
