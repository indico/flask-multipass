# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals


class MultiAuth(object):
    """Base class of the Flask-MultiAuth extension.

    :param app: The flask application. If omitted, use :meth:`init_app`
                to initialize the extension for you application.
    """

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the extension for a Flask application.

        This is only necessary if the application was not provided in the
        constructor, e.g. because there is more than one application or you
        are using an application factory.

        :param app: The flask application
        """
        if 'multiauth' in app.extensions:
            raise RuntimeError('Flask application already initialized')
        app.extensions['multiauth'] = self
