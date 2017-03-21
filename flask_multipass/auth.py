# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask_multipass._compat import add_metaclass
from flask_multipass.util import SupportsMeta


@add_metaclass(SupportsMeta)
class AuthProvider(object):
    """Provides the base for an authentication provider.

    :param multipass: The Flask-Multipass instance
    :param name: The name of this auth provider instance
    :param settings: The settings dictionary for this auth provider
                     instance
    """

    __support_attrs__ = {
        SupportsMeta.callable(lambda cls: cls.login_form is not None,
                              'login_form is set'): 'process_local_login',
        SupportsMeta.callable(lambda cls: cls.login_form is None,
                              'login_form is not set'): 'initiate_external_login'
    }
    #: The entry point to lookup providers (do not override this!)
    _entry_point = 'flask_multipass.auth_providers'
    #: If there may be multiple instances of this auth provider
    multi_instance = True
    #: If this auth provider requires the user to enter data using a
    #: form in your application, specify a :class:`~flask_wtf.Form`
    #: here (usually containing a username/email and a password field).
    login_form = None

    def __init__(self, multipass, name, settings):
        self.multipass = multipass
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

    def process_local_login(self, data):  # pragma: no cover
        """Handles the login process based on form data.

        Only called if the login form validates successfully.
        This method needs to verify the form data actually contains
        valid credentials.

        After successful authentication this method needs to call
        :meth:`.Multipass.handle_auth_success` with an :class:`.AuthInfo`
        instance containing data that can be used by the identity provider
        to retrieve information for that user.

        :param data: The form data (as returned by the `data` attribute
                      of the :obj:`login_form` instance)
        :return: The return value of :meth:`.Multipass.handle_auth_success`
        """
        if not self.is_external:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider has no login form')

    def initiate_external_login(self):  # pragma: no cover
        """Initiates the login process for external authentication.

        Called when the provider is selected and has no login form.
        This method usually redirects to an external login page.

        Executing this method eventually needs to result in a call to
        :meth:`.Multipass.handle_auth_success` with an :class:`.AuthInfo`
        instance containing data that can be used by the identity provider
        to retrieve information for that user.

        The most common way to achieve this is registering a new
        endpoint (decorated with :func:`.login_view`) and passing the
        URL of that endpoint to the external provider so it redirects
        to it once the user authenticated with that provider.

        :return: A Flask :class:`~flask.Response`, usually created by
                 :func:`~flask.redirect`
        """
        if self.is_external:
            raise NotImplementedError
        else:
            raise RuntimeError('This provider uses a login form')

    def process_logout(self, return_url):
        """Handles logging out from the provider.

        This is only necessary if logging out from the application
        needs to perform some provider-specific action such as sending
        a logout notification to the provider or redirecting to a SSO
        logout page.

        If a value is returned, it's eventually returned to Flask as a
        view function return value, so anything that's valid there can
        be used. Most likely you want to use :func:`~flask.redirect`
        to redirect to an external logout page though.

        When redirecting to an external site, you should pass along the
        `return_url` if the external provider allows you to specify a
        URL to redirect to after logging out.

        :param return_url: The URL to redirect to after logging our.
        :return: ``None`` or a Flask response.
        """
        return None

    def __repr__(self):
        return '<{}({})>'.format(type(self).__name__, self.name)
