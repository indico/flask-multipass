# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import pytest
from flask import Flask, request

from flask_multiauth import MultiAuth, AuthProvider


def test_init_app_twice():
    multiauth = MultiAuth()
    app = Flask('test')
    multiauth.init_app(app)
    with pytest.raises(RuntimeError):
        multiauth.init_app(app)


def test_init_app_late():
    app = Flask('text')
    multiauth = MultiAuth()
    multiauth.init_app(app)
    assert app.extensions['multiauth'].multiauth is multiauth


def test_init_app_immediately():
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


def test_initialize_once(mocker):
    create_login_rule = mocker.patch.object(MultiAuth, '_create_login_rule')
    app = Flask('test')
    multiauth = MultiAuth(app)
    assert not create_login_rule.called
    multiauth.initialize(app)
    assert create_login_rule.call_count == 1
    multiauth.initialize(app)
    assert create_login_rule.call_count == 1


@pytest.fixture
def mock_auth_providers(monkeypatch):
    class FooProvider(AuthProvider):
        type = 'foo'

    class UniqueProvider(AuthProvider):
        type = 'unique'
        multi_instance = False

    mapping = {'foo': FooProvider,
               'unique': UniqueProvider}
    monkeypatch.setattr('flask_multiauth.core.resolve_provider_type', lambda _, t: mapping[t])


@pytest.mark.usefixtures('mock_auth_providers')
def test_initialize_providers():
    app = Flask('test')
    multiauth = MultiAuth(app)
    app.config['MULTIAUTH_AUTH_PROVIDERS'] = {
        'test': {'type': 'foo', 'foo': 'bar'},
        'test2': {'type': 'unique', 'hello': 'world'},
    }
    with app.app_context():
        multiauth.initialize(app)
        assert multiauth.auth_providers['test'].settings == {'foo': 'bar'}
        assert multiauth.auth_providers['test2'].settings == {'hello': 'world'}


@pytest.mark.usefixtures('mock_auth_providers')
def test_initialize_providers_unique():
    app = Flask('test')
    multiauth = MultiAuth(app)
    app.config['MULTIAUTH_AUTH_PROVIDERS'] = {
        'test': {'type': 'unique', 'foo': 'bar'},
        'test2': {'type': 'unique', 'hello': 'world'},
    }
    with app.app_context():
        with pytest.raises(RuntimeError):
            multiauth.initialize(app)


def test_create_login_rule(mocker):
    process_login = mocker.patch.object(MultiAuth, 'process_login')
    app = Flask('test')
    multiauth = MultiAuth(app)
    multiauth.initialize(app)
    with app.test_client() as c:
        for url in app.config['MULTIAUTH_LOGIN_URLS']:
            c.get(url)
    assert process_login.call_count == 2


def test_create_login_rule_disabled(mocker):
    process_login = mocker.patch.object(MultiAuth, 'process_login')
    app = Flask('test')
    multiauth = MultiAuth(app)
    urls = app.config['MULTIAUTH_LOGIN_URLS']  # default urls
    app.config['MULTIAUTH_LOGIN_URLS'] = None
    multiauth.initialize(app)
    with app.test_client() as c:
        for url in urls:
            assert c.get(url).status_code == 404
    assert not process_login.called


def test_render_template(mocker):
    render_template = mocker.patch('flask_multiauth.core.render_template')
    app = Flask('test')
    app.config['MULTIAUTH_FOO_TEMPLATE'] = None
    app.config['MULTIAUTH_BAR_TEMPLATE'] = 'bar.html'
    multiauth = MultiAuth(app)
    multiauth.initialize(app)
    with app.app_context():
        with pytest.raises(RuntimeError):
            multiauth.render_template('FOO', foo='bar')
        multiauth.render_template('BAR', foo='bar')
        render_template.assert_called_with('bar.html', foo='bar')


def test_next_url():
    app = Flask('test')
    app.add_url_rule('/success', 'success')
    app.config['SECRET_KEY'] = 'testing'
    app.config['MULTIAUTH_SUCCESS_ENDPOINT'] = 'success'
    multiauth = MultiAuth(app)
    multiauth.initialize(app)
    with app.test_request_context():
        # default url - not in session
        assert multiauth._get_next_url() == '/success'
        multiauth._set_next_url()
        # default url - in session
        assert multiauth._get_next_url() == '/success'
        request.args = {'next': '/private'}
        # next url specified, but not in session yet
        assert multiauth._get_next_url() == '/success'
        multiauth._set_next_url()
        # removed from session after retrieving it once
        assert multiauth._get_next_url() == '/private'
        assert multiauth._get_next_url() == '/success'
