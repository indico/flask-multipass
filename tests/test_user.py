# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import pytest

from flask_multiauth import UserProvider


def test_settings_copied():
    settings = {'foo': 'bar'}
    provider = UserProvider(None, None, settings)
    provider.settings['foo'] = 'foobar'
    assert settings['foo'] == 'bar'


@pytest.mark.parametrize(('settings', 'title'), (
    ({}, 'foo'),
    ({'title': 'whatever'}, 'whatever'),
))
def test_settings_title(settings, title):
    provider = UserProvider(None, 'foo', settings)
    assert provider.title == title
