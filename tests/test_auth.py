# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

import pytest

from flask_multipass import AuthProvider


class LocalProvider(AuthProvider):
    login_form = object()


class RemoteProvider(AuthProvider):
    pass


def test_is_external():
    assert not LocalProvider(None, None, {}).is_external
    assert RemoteProvider(None, None, {}).is_external


def test_settings_copied():
    settings = {'foo': 'bar'}
    provider = LocalProvider(None, None, settings)
    provider.settings['foo'] = 'foobar'
    assert settings['foo'] == 'bar'


@pytest.mark.parametrize(('settings', 'title'), (
    ({}, 'foo'),
    ({'title': 'whatever'}, 'whatever'),
))
def test_settings_title(settings, title):
    provider = LocalProvider(None, 'foo', settings)
    assert provider.title == title
