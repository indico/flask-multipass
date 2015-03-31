# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import pytest
from flask import Flask

from flask_multiauth import MultiAuth


def test_init_twice():
    multiauth = MultiAuth()
    app = Flask('test')
    multiauth.init_app(app)
    with pytest.raises(RuntimeError):
        multiauth.init_app(app)


def test_init_late():
    app = Flask('text')
    multiauth = MultiAuth()
    multiauth.init_app(app)
    assert app.extensions['multiauth'].multiauth is multiauth


def test_init_immediately():
    app = Flask('test')
    multiauth = MultiAuth(app)
    assert app.extensions['multiauth'].multiauth is multiauth


def test_multiple_apps():
    apps = Flask('test'), Flask('test')
    multiauth = MultiAuth()
    for app in apps:
        multiauth.init_app(app)
    # The separate loop here is on purpose as the extension needs to
    # be present on all apps after initializing them
    for app in apps:
        assert app.extensions['multiauth'].multiauth is multiauth
