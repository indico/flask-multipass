# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals


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

    def __repr__(self):
        data = ', '.join('{}={!r}'.format(k, v) for k, v in self.data.items())
        return '<AuthInfo({}, {})>'.format(self.provider, data)
