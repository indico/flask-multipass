# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import pytest
from flask import Flask

from flask_multiauth import UserProvider, MultiAuth


def test_settings_copied():
    app = Flask('test')
    MultiAuth(app)
    with app.app_context():
        settings = {'foo': 'bar'}
        provider = UserProvider(None, None, settings)
        provider.settings['foo'] = 'foobar'
        assert settings['foo'] == 'bar'


@pytest.mark.parametrize(('settings', 'title'), (
    ({}, 'foo'),
    ({'title': 'whatever'}, 'whatever'),
))
def test_settings_title(settings, title):
    app = Flask('test')
    MultiAuth(app)
    with app.app_context():
        provider = UserProvider(None, 'foo', settings)
        assert provider.title == title


@pytest.mark.parametrize(('criteria', 'mapping', 'result'), (
    ({'foo': 'bar'}, {},                           {'foo': 'bar'}),
    ({'foo': 'bar'}, {'foo': 'moo'},               {'moo': 'bar'}),
    ({'foo': 'bar'}, {'foo': 'moo', 'bar': 'moo'}, {'moo': 'bar'}),
))
def test_map_search_criteria(criteria, mapping, result):
    app = Flask('test')
    MultiAuth(app)
    with app.app_context():
        settings = {'mapping': mapping}
        provider = UserProvider(None, 'foo', settings)
        assert provider.map_search_criteria(criteria) == result
