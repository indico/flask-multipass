# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals


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

    def __init__(self, multiauth, name, settings):
        self.multiauth = multiauth
        self.name = name
        self.settings = settings.copy()
        self.title = self.settings.pop('title', self.name)

    def __repr__(self):
        return '<{}({}, {})>'.format(type(self).__name__, self.type, self.name)
