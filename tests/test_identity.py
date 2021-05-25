# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

import pytest
from flask import Flask

from flask_multipass import IdentityProvider, Multipass


def test_settings_copied():
    app = Flask('test')
    Multipass(app)
    with app.app_context():
        settings = {'foo': 'bar'}
        provider = IdentityProvider(None, None, settings)
        provider.settings['foo'] = 'foobar'
        assert settings['foo'] == 'bar'


@pytest.mark.parametrize(('settings', 'title'), (
    ({}, 'foo'),
    ({'title': 'whatever'}, 'whatever'),
))
def test_settings_title(settings, title):
    app = Flask('test')
    Multipass(app)
    with app.app_context():
        provider = IdentityProvider(None, 'foo', settings)
        assert provider.title == title


@pytest.mark.parametrize(('criteria', 'mapping', 'result'), (
    ({'foo': 'bar'}, {},                           {'foo': 'bar'}),
    ({'foo': 'bar'}, {'foo': 'moo'},               {'moo': 'bar'}),
    ({'foo': 'bar'}, {'foo': 'moo', 'bar': 'moo'}, {'moo': 'bar'}),
))
def test_map_search_criteria(criteria, mapping, result):
    app = Flask('test')
    Multipass(app)
    with app.app_context():
        settings = {'mapping': mapping}
        provider = IdentityProvider(None, 'foo', settings)
        assert provider.map_search_criteria(criteria) == result
