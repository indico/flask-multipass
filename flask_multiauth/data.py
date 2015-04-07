# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask_multiauth._compat import iteritems


class AuthInfo(object):
    """Stores data from an authentication provider.

    :param provider: The authentication provider instance providing
                     the data.
    :param data: Any data the authentication provider wants to pass on
                 to user providers. This data must allow any connected
                 user provider to uniquely identify a user.
    """

    def __init__(self, provider, **data):
        self.provider = provider
        self.data = data
        if not data:
            raise ValueError('data cannot be empty')

    def map(self, mapping):
        """Creates a new instance with transformed data keys

        :param mapping: The dict mapping the current data keys to the
                        the keys that are expected by the user provider.
                        Any key that is not in `mapping` is kept as-is.
        """
        mapped_keys = set(mapping.values())
        data = {key: value for key, value in iteritems(self.data) if key not in mapped_keys}
        data.update((target_key, self.data[source_key]) for target_key, source_key in iteritems(mapping))
        return AuthInfo(self.provider, **data)

    def __repr__(self):
        data = ', '.join('{}={!r}'.format(k, v) for k, v in self.data.items())
        return '<AuthInfo({}, {})>'.format(self.provider, data)


class UserInfo(object):
    """Stores user information for the application.

    :param provider: The user provider instance providing the data.
    :param identifier: A unique identifier string that can later be
                       used to retrieve user data for the same user.
    :param refresh_data: A dict containing additional data the user
                         provider needs to refresh the user information
                         for the same user, without him authenticating
                         again. This could for example be a long-lived
                         access token from the auth provider.
    :param data: Any data the user provider wants to pass on the
                 application.
    """

    def __init__(self, provider, identifier, refresh_data=None, **data):
        self.provider = provider
        self.identifier = identifier
        if not provider.supports_refresh:
            assert refresh_data is None
            self.refresh_data = None
        else:
            self.refresh_data = dict(refresh_data or {}, _provider=provider.name)
        self.data = data

    def __repr__(self):
        data = ', '.join('{}={!r}'.format(k, v) for k, v in self.data.items())
        return '<UserInfo({}, {}, {})>'.format(self.provider, self.identifier, data or None)
