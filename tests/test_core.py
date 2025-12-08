# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from unittest.mock import Mock

import pytest
from flask import Flask, request, session

from flask_multipass import AuthenticationFailed, AuthProvider, Multipass


def test_init_app_twice():
    multipass = Multipass()
    app = Flask('test')
    multipass.init_app(app)
    with pytest.raises(RuntimeError):
        multipass.init_app(app)


def test_init_app_late():
    app = Flask('text')
    multipass = Multipass()
    multipass.init_app(app)
    assert app.extensions['multipass'].multipass is multipass


def test_init_app_immediately():
    app = Flask('test')
    multipass = Multipass(app)
    assert app.extensions['multipass'].multipass is multipass


def test_multiple_apps():
    apps = Flask('test'), Flask('test')
    multipass = Multipass()
    for app in apps:
        multipass.init_app(app)
    # The separate loop here is on purpose as the extension needs to
    # be present on all apps after initializing them
    for app in apps:
        assert app.extensions['multipass'].multipass is multipass


class FooProvider(AuthProvider):
    pass


class UniqueProvider(AuthProvider):
    multi_instance = False


def test_initialize_providers():
    app = Flask('test')
    app.config['MULTIPASS_AUTH_PROVIDERS'] = {
        'test': {'type': 'foo', 'foo': 'bar'},
        'test2': {'type': 'unique', 'hello': 'world'},
    }
    multipass = Multipass()
    multipass.register_provider(FooProvider, 'foo')
    multipass.register_provider(UniqueProvider, 'unique')
    with app.app_context():
        auth_providers = multipass._create_providers('AUTH', AuthProvider)
        assert auth_providers['test'].settings == {'foo': 'bar'}
        assert auth_providers['test2'].settings == {'hello': 'world'}


def test_initialize_providers_unique():
    app = Flask('test')
    app.config['MULTIPASS_AUTH_PROVIDERS'] = {
        'test': {'type': 'unique', 'foo': 'bar'},
        'test2': {'type': 'unique', 'hello': 'world'},
    }
    multipass = Multipass()
    multipass.register_provider(FooProvider, 'foo')
    multipass.register_provider(UniqueProvider, 'unique')
    with pytest.raises(RuntimeError):
        multipass.init_app(app)


def test_create_login_rule(mocker):
    process_login = mocker.patch.object(Multipass, 'process_login')
    app = Flask('test')
    Multipass(app)
    with app.test_client() as c:
        for url in app.config['MULTIPASS_LOGIN_URLS']:
            c.get(url)
    assert process_login.call_count == 2


def test_create_login_rule_disabled(mocker):
    process_login = mocker.patch.object(Multipass, 'process_login')
    app = Flask('test')
    app.config['MULTIPASS_LOGIN_URLS'] = None
    Multipass(app)
    with app.test_client() as c:
        for url in ('/login/', '/login/<provider>'):
            assert c.get(url).status_code == 404
    assert not process_login.called


def test_render_template(mocker):
    render_template = mocker.patch('flask_multipass.core.render_template')
    app = Flask('test')
    app.config['MULTIPASS_FOO_TEMPLATE'] = None
    app.config['MULTIPASS_BAR_TEMPLATE'] = 'bar.html'
    multipass = Multipass(app)
    with app.app_context():
        with pytest.raises(RuntimeError):
            multipass.render_template('FOO', foo='bar')
        multipass.render_template('BAR', foo='bar')
        render_template.assert_called_with('bar.html', foo='bar')


def test_next_url():
    app = Flask('test')
    app.add_url_rule('/success', 'success')
    app.config['SECRET_KEY'] = 'testing'
    app.config['MULTIPASS_SUCCESS_ENDPOINT'] = 'success'
    multipass = Multipass(app)
    with app.test_request_context():
        # default url - not in session
        assert multipass._get_next_url() == '/success'
        multipass.set_next_url()
        # default url - in session
        assert multipass._get_next_url() == '/success'
        request.args = {'next': '/private'}
        # next url specified, but not in session yet
        assert multipass._get_next_url() == '/success'
        multipass.set_next_url()
        # removed from session after retrieving it once
        assert multipass._get_next_url() == '/private'
        assert multipass._get_next_url() == '/success'


def test_next_url_invalid():
    app = Flask('test')
    app.add_url_rule('/success', 'success')
    app.config['SECRET_KEY'] = 'testing'
    app.config['MULTIPASS_SUCCESS_ENDPOINT'] = 'success'
    multipass = Multipass(app)
    with app.test_request_context():
        request.args = {'next': '//evil.com'}
        multipass.set_next_url()
        assert multipass._get_next_url() == '/success'


@pytest.mark.parametrize(('url', 'valid'), (
    ('foo', True),
    ('/foo', True),
    ('/foo?bar', True),
    ('/foo#bar', True),
    ('//localhost', True),
    ('//localhost/foo', True),
    ('http://localhost', True),
    ('https://localhost/', True),
    ('\n', False),
    ('\r', False),
    ('\n\r', False),
    ('evil\n', False),
    ('//evil', False),
    ('//evil.com', False),
    ('//evil.com:80', False),
    ('///evil', False),
    ('///evil.com', False),
    ('///evil.com:80', False),
    ('////evil', False),
    ('////evil.com', False),
    ('////evil.com:80', False),
    ('http://evil.com', False),
    ('https://evil.com', False),
    (r'http:\\evil.com', False),
    (r'http:\evil.com', False),
    (r'https:\\evil.com', False),
    (r'https:\evil.com', False),
    ('javascript:alert("eeeeeeeevil")', False),
    ('///localhost', False),
    ('////localhost', False),
))
def test_validate_next_url(url, valid):
    app = Flask('test')
    multipass = Multipass(app)
    with app.test_request_context():
        assert multipass.validate_next_url(url) == valid


def test_login_finished():
    multipass = Multipass()
    with pytest.raises(AssertionError):
        multipass.login_finished(None)
    callback = Mock()
    multipass.identity_handler(callback)
    multipass.login_finished('foo')
    callback.assert_called_with('foo')


def test_login_finished_returns():
    multipass = Multipass()
    multipass.identity_handler(Mock(return_value='bar'))
    assert multipass.login_finished('foo') == 'bar'


def test_identity_handler():
    multipass = Multipass()
    callback = Mock()
    assert multipass.identity_handler(callback) is callback


def test_login_check():
    multipass = Multipass()
    callback = Mock()
    assert multipass.login_check(callback) is callback


def test_handle_auth_error(mocker):
    flash = mocker.patch('flask_multipass.core.flash')
    app = Flask('test')
    app.config['SECRET_KEY'] = 'testing'
    multipass = Multipass(app)
    with app.test_request_context():
        multipass.handle_auth_error(AuthenticationFailed())
        assert flash.called
        assert session['_multipass_auth_failed']


def test_handle_auth_error_with_redirect(mocker):
    flash = mocker.patch('flask_multipass.core.flash')
    redirect = mocker.patch('flask_multipass.core.redirect')
    app = Flask('test')
    app.config['SECRET_KEY'] = 'testing'
    multipass = Multipass(app)
    with app.test_request_context():
        multipass.handle_auth_error(AuthenticationFailed(), redirect_to_login=True)
        assert flash.called
        redirect.assert_called_with(app.config['MULTIPASS_LOGIN_URLS'][0])


def test_load_providers_from_entrypoints():
    app = Flask('test')
    app.config['SECRET_KEY'] = 'testing'
    app.config['MULTIPASS_AUTH_PROVIDERS'] = {'test': {'type': 'static'}}
    app.config['MULTIPASS_IDENTITY_PROVIDERS'] = {'test': {'type': 'static'}}
    app.config['MULTIPASS_PROVIDER_MAP'] = {'test': 'test'}
    Multipass(app)
