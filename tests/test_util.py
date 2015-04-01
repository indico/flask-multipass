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
from flask_multiauth.util import classproperty, get_state, resolve_provider_type


def test_get_state_app_not_initialized():
    app = Flask('test')
    with pytest.raises(AssertionError):
        get_state(app)


def test_get_state_explicit():
    app = Flask('test')
    app2 = Flask('test2')
    multiauth = MultiAuth()
    multiauth.init_app(app)
    multiauth.initialize(app)
    multiauth.init_app(app2)
    multiauth.initialize(app2)
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
    multiauth.initialize(app)
    with app.app_context():
        state = get_state(app)
        assert state.multiauth is multiauth
        assert state.app is app
        assert get_state(app) is state


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
