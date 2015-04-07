# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from pkg_resources import EntryPoint

import pytest
from flask import Flask

from flask_multiauth import MultiAuth
from flask_multiauth._compat import iteritems
from flask_multiauth.core import _MultiAuthState
from flask_multiauth.exceptions import AuthenticationFailed
from flask_multiauth.util import (classproperty, get_state, resolve_provider_type, convert_data, login_view,
                                  get_canonical_provider_map, validate_provider_map)


@pytest.mark.parametrize(('config_map', 'canonical_map'), (
    ({'foo': 'bar'},                             {'foo': ({'user_provider': 'bar'},)}),
    ({'foo': ['bar']},                           {'foo': ({'user_provider': 'bar'},)}),
    ({'foo': {'bar'}},                           {'foo': ({'user_provider': 'bar'},)}),
    ({'foo': {'user_provider': 'bar'}},          {'foo': ({'user_provider': 'bar'},)}),
    ({'foo': [{'user_provider': 'bar'}]},        {'foo': ({'user_provider': 'bar'},)}),
    ({'foo': [{'user_provider': 'bar'}, 'moo']}, {'foo': ({'user_provider': 'bar'},
                                                          {'user_provider': 'moo'})}),
    ({'foo': 'bar', 'meow': 'moo'},              {'foo': ({'user_provider': 'bar'},),
                                                  'meow': ({'user_provider': 'moo'},)}),
))
def test_get_canonical_provider_map(config_map, canonical_map):
    assert get_canonical_provider_map(config_map) == canonical_map


def test_get_state_app_not_initialized():
    app = Flask('test')
    with pytest.raises(AssertionError):
        get_state(app)


def test_get_state_explicit():
    app = Flask('test')
    app2 = Flask('test2')
    multiauth = MultiAuth()
    multiauth.init_app(app)
    multiauth.init_app(app2)
    # outside app ctx
    with pytest.raises(RuntimeError):
        assert get_state().app
    # explicit app
    assert get_state(app2).app is app2
    # explicit app inside other app context (unlikely)
    with app.app_context():
        assert get_state(app2).app is app2


def test_get_state():
    app = Flask('test')
    multiauth = MultiAuth(app)
    with app.app_context():
        state = get_state(app)
        assert state.multiauth is multiauth
        assert state.app is app
        assert get_state(app) is state


@pytest.mark.parametrize(('data', 'mapping', 'keys', 'result'), (
    ({'foo': 'bar'},               {},                        None,          {'foo': 'bar'}),
    ({'foo': 'bar', 'a': 'value'}, {'test': 'foo'},           None,          {'test': 'bar', 'a': 'value'}),
    ({'foo': 'bar', 'a': 'value'}, {'test': 'foo', 'x': 'y'}, None,          {'test': 'bar', 'x': None, 'a': 'value'}),
    ({'foo': 'bar'},               {},                        [],            {}),
    ({'foo': 'bar', 'a': 'value'}, {'test': 'foo', 'x': 'y'}, {'test', 'x'}, {'test': 'bar', 'x': None}),
))
def test_map_data(data, mapping, keys, result):
    assert convert_data(data, mapping, keys) == result


def test_login_view(mocker):
    handle_auth_error = mocker.patch.object(MultiAuth, 'handle_auth_error')
    app = Flask('test')
    e = AuthenticationFailed()

    @app.route('/ok')
    @login_view
    def ok():
        return ''

    @app.route('/err')
    @login_view
    def err():
        raise Exception()

    @app.route('/fail')
    @login_view
    def fail():
        raise e

    MultiAuth(app)
    with app.test_client() as c:
        c.get('/ok')
        assert not handle_auth_error.called
        c.get('/err')
        assert not handle_auth_error.called
        c.get('/fail')
        handle_auth_error.assert_called_with(e, True)


class DummyBase(object):
    _entry_point = 'dummy'


class Dummy(DummyBase):
    pass


class FakeDummy(object):
    pass


class MockEntryPoint(EntryPoint):
    def load(self, *args, **kwargs):
        mapping = {
            'dummy': Dummy,
            'fake': FakeDummy,
        }
        return mapping[self.name]


@pytest.fixture
def mock_entry_point(monkeypatch):
    def _mock_iter_entry_points(_, name):
        return {
            'dummy': [MockEntryPoint('dummy', 'who.cares')],
            'fake': [MockEntryPoint('fake', 'who.cares')],
            'multi': [MockEntryPoint('dummy', 'who.cares'), MockEntryPoint('fake', 'who.cares')],
            'unknown': []
        }[name]

    monkeypatch.setattr('flask_multiauth.util.iter_entry_points', _mock_iter_entry_points)


def test_resolve_provider_type_class():
    assert resolve_provider_type(DummyBase, Dummy) is Dummy
    with pytest.raises(TypeError):
        resolve_provider_type(DummyBase, FakeDummy)


@pytest.mark.usefixtures('mock_entry_point')
def test_resolve_provider_type_invalid():
    # unknown type
    with pytest.raises(ValueError):
        assert resolve_provider_type(DummyBase, 'unknown')
    # non-unique type
    with pytest.raises(RuntimeError):
        assert resolve_provider_type(DummyBase, 'multi')
    # invalid type
    with pytest.raises(TypeError):
        assert resolve_provider_type(DummyBase, 'fake')


@pytest.mark.usefixtures('mock_entry_point')
def test_resolve_provider_type():
    assert resolve_provider_type(DummyBase, 'dummy') is Dummy


@pytest.mark.parametrize(('valid', 'auth_providers', 'user_providers', 'provider_map'), (
    (False, ['a'], [],    {}),
    (False, ['a'], ['a'], {}),
    (False, ['a'], ['b'], {}),
    (False, ['a'], ['b'], {'a': 'c'}),
    (True,  ['a'], ['b'], {'a': 'b'}),
    (True,  [],    ['b'], {'a': 'b'}),
))
def test_validate_provider_map(valid, auth_providers, user_providers, provider_map):
    state = _MultiAuthState(None, None)
    state.auth_providers = {x: {} for x in auth_providers}
    state.user_providers = {x: {} for x in user_providers}
    state.provider_map = {a: [{'user_provider': u}] for a, u in iteritems(provider_map)}
    if valid:
        validate_provider_map(state)
    else:
        pytest.raises(ValueError, validate_provider_map, state)


def test_classproperty():
    class Foo(object):
        @classproperty
        @classmethod
        def bar(cls):
            return 'foobar'

    class B(Foo):
        pass

    class C(Foo):
        pass

    assert Foo.bar == 'foobar'
    assert B.bar == 'foobar'
    assert C.bar == 'foobar'
    B.bar = 'moo'
    assert Foo.bar == 'foobar'
    assert B.bar == 'moo'
    assert C.bar == 'foobar'
    Foo.bar = 'asdf'
    assert Foo.bar == 'asdf'
    assert B.bar == 'moo'
    assert C.bar == 'asdf'
    inst = Foo()
    assert inst.bar == 'asdf'
    inst.bar = 'xyz'
    assert inst.bar == 'xyz'
    assert Foo.bar == 'asdf'
