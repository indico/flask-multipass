# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from unittest.mock import MagicMock

import pytest

from flask_multipass import AuthInfo, AuthProvider, IdentityInfo, Multipass


@pytest.fixture(name='dummy_auth_provider')
def dummy_auth_provider_fixture():
    return AuthProvider(Multipass(), 'dummy', {})


def test_authinfo(dummy_auth_provider):
    with pytest.raises(ValueError):
        AuthInfo(dummy_auth_provider)
    ai = AuthInfo(dummy_auth_provider, foo='bar')
    assert ai.data == {'foo': 'bar'}


@pytest.mark.parametrize(('mapping', 'output_data'), (
    ({},             {'foo': 'bar', 'meow': 1337}),
    ({'oof': 'foo'}, {'oof': 'bar', 'meow': 1337}),
))
def test_authinfo_map(dummy_auth_provider, mapping, output_data):
    ai = AuthInfo(dummy_auth_provider, foo='bar', meow=1337)
    original_data = ai.data.copy()
    ai2 = ai.map(mapping)
    assert ai2.data == output_data
    assert ai.data == original_data


def test_authinfo_map_invalid(dummy_auth_provider):
    ai = AuthInfo(dummy_auth_provider, foo='bar')
    with pytest.raises(KeyError):
        ai.map({'foo': 'nop'})


def test_identityinfo_identifier_string():
    assert IdentityInfo(MagicMock(), 123).identifier == '123'
