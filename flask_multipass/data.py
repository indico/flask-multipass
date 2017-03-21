# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from werkzeug.datastructures import MultiDict

from flask_multipass._compat import text_type
from flask_multipass.util import convert_provider_data


class AuthInfo(object):
    """Stores data from an authentication provider.

    :param provider: The authentication provider instance providing
                     the data.
    :param data: Any data the authentication provider wants to pass on
                 to identity providers. This data must allow any
                 connected identity provider to uniquely identify a user.
    """

    def __init__(self, provider, **data):
        self.provider = provider
        self.data = data
        if not data:
            raise ValueError('data cannot be empty')

    def map(self, mapping):
        """Creates a new instance with transformed data keys

        :param mapping: The dict mapping the current data keys to the
                        the keys that are expected by the identity
                        provider. Any key that is not in `mapping` is
                        kept as-is.
        """
        missing_keys = set(mapping.values()) - set(self.data)
        if missing_keys:
            raise KeyError(next(iter(missing_keys)))
        return AuthInfo(self.provider, **convert_provider_data(self.data, mapping))

    def __repr__(self):
        data = ', '.join('{}={!r}'.format(k, v) for k, v in sorted(self.data.items()))
        return '<AuthInfo({}, {})>'.format(self.provider, data)


class IdentityInfo(object):
    """Stores user identity information for the application.

    :param provider: The identity provider instance providing the data.
    :param identifier: A unique identifier string that can later be
                       used to retrieve identity information for the
                       same user.
    :param multipass_data: A dict containing additional data the
                           identity provider needs e.g. to refresh the
                           identity information for the same user,
                           without him authenticating again by keeping a
                           long-lived token.
    :param data: Any data the identity provider wants to pass on the
                 application.
    """

    def __init__(self, provider, identifier, multipass_data=None, **data):
        self.provider = provider
        self.identifier = text_type(identifier)
        if not provider.supports_refresh:
            assert multipass_data is None
            self.multipass_data = None
        else:
            self.multipass_data = dict(multipass_data or {}, _provider=provider.name)
        mapping = provider.settings.get('mapping')
        self.data = MultiDict(convert_provider_data(data, mapping or {}, self.provider.settings['identity_info_keys']))

    def __repr__(self):
        data = ', '.join('{}={!r}'.format(k, v) for k, v in sorted(self.data.items()))
        return '<IdentityInfo({}, {}, {})>'.format(self.provider, self.identifier, data or None)
