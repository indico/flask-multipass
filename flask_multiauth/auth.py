# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals


class AuthProvider(object):
    """Provides the base for an authentication provider.

    :param multiauth: The Flask-MultiAuth instancee
    :param name: The name of this auth provider instance
    :param settings: The settings dictionary for this auth provider
                     instance
    """

    _entry_point = 'flask_multiauth.auth_providers'
    #: The unique identifier of the auth provider
    type = None
    #: If there may be multiple instances of this auth provider
    multi_instance = True
    #: If this auth provider requires the user to enter data using a
    #: form in your application, specify a :class:`~flask_wtf.Form`
    #: here (usually containing a username/email and a password field).
    login_form = None

    def __init__(self, multiauth, name, settings):
        self.multiauth = multiauth
        self.name = name
        self.settings = settings.copy()
        self.title = self.settings.pop('title', self.name)

    @property
    def is_external(self):
        """True if the provider is external.

        External providers do not have a login form and instead
        redirect to a third-party service to perform authentication.
        """
        return self.login_form is None

    def process_local_login(self, data):
        """Called after successful validation of the login form

        :param data: The form data (as returned by the `data` attribute
                      of the :obj:`login_form` instance)
        :return: An :class:`.AuthInfo` instance containing data that can
                 be used to uniquely identify the user
        """
        if not self.is_external:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider has no login form')

    def initiate_external_login(self):
        """Called when the provider is selected and has no login form

        :return: A Flask :class:`~flask.Response`, usually created by
                 :func:`~flask.redirect`
        """
        if self.is_external:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider uses a login form')

    def __repr__(self):
        return '<{}({})>'.format(self.type, self.name)
