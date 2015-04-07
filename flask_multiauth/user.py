# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask import current_app

from flask_multiauth._compat import iteritems


class UserProvider(object):
    """Provides the base for a user provider.

    :param multiauth: The Flask-MultiAuth instancee
    :param name: The name of this user provider instance
    :param settings: The settings dictionary for this user provider
                     instance
    """

    #: The entry point to lookup providers (do not override this!)
    _entry_point = 'flask_multiauth.user_providers'
    #: The unique identifier of the user provider
    type = None
    #: If there may be multiple instances of this user provider
    multi_instance = True
    #: If the provider supports refreshing user information
    supports_refresh = False
    #: If the provider supports searching users
    supports_search = False

    def __init__(self, multiauth, name, settings):
        self.multiauth = multiauth
        self.name = name
        self.settings = settings.copy()
        self.settings.setdefault('user_info_keys', current_app.config['MULTIAUTH_USER_INFO_KEYS'])
        self.settings.setdefault('mapping', {})
        self.title = self.settings.pop('title', self.name)
        search_enabled = self.settings.pop('search_enabled', self.supports_search)
        if search_enabled and not self.supports_search:
            raise ValueError('Provider does not support searching: ' + self.type)
        self.supports_search = search_enabled

    def get_user_from_auth(self, auth_info):  # pragma: no cover
        """Retrieves user information after authentication

        :param auth_info: An :class:`.AuthInfo` instance from an auth
                          provider
        :return: A :class:`.UserInfo` instance containing user
                 information or ``None`` if no user was found
        """
        raise NotImplementedError

    def refresh_user(self, identifier, refresh_data):  # pragma: no cover
        """Retrieves user information for an existing user

        This method returns user information for a user who has been
        retrieved before based on the provider-specific refresh data.

        :param identifier: The `identifier` from :class:`.UserInfo`
        :param refresh_data: The `refresh_data` dict from
                             :class:`.UserInfo`
        """
        if self.supports_refresh:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider does not support refreshing')

    def search_users(self, criteria, exact=False):  # pragma: no cover
        """Searches users matching certain criteria

        :param criteria: A dict containing the criteria to search for.
        :param exact: If criteria need to match exactly, i.e. no
                      substring matches are performed.
        :return: An iterable of matching users.
        """
        if self.supports_search:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider does not support searching')

    def map_search_criteria(self, criteria):
        """Maps the search criteria from application keys to provider keys

        :param criteria: A dict containing search criteria
        :return: A dict containing search criteria with mapped keys
        """
        mapping = self.settings['mapping']
        return {mapping.get(key, key): value for key, value in iteritems(criteria)}

    def __repr__(self):
        return '<{}({}, {})>'.format(type(self).__name__, self.type, self.name)
