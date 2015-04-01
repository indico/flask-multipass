# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask import current_app, render_template, request, url_for, session, redirect, flash
from werkzeug.datastructures import ImmutableDict
from werkzeug.exceptions import NotFound

from flask_multiauth._compat import iteritems, text_type
from flask_multiauth.auth import AuthProvider
from flask_multiauth.exceptions import AuthenticationFailed
from flask_multiauth.util import get_state, resolve_provider_type


class MultiAuth(object):
    """Base class of the Flask-MultiAuth extension.

    :param app: The flask application. If omitted, use :meth:`init_app`
                to initialize the extension for you application.
    """

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the extension for a Flask application.

        This is only necessary if the application was not provided in the
        constructor, e.g. because there is more than one application or you
        are using an application factory.

        :param app: The flask application
        """
        if 'multiauth' in app.extensions:
            raise RuntimeError('Flask application already initialized')
        app.extensions['multiauth'] = _MultiAuthState(self, app)
        # TODO: write docs for the config (see flask-cache for a pretty example)
        app.config.setdefault('MULTIAUTH_AUTH_PROVIDERS', {})
        app.config.setdefault('MULTIAUTH_LOGIN_SELECTOR_TEMPLATE', None)
        app.config.setdefault('MULTIAUTH_LOGIN_FORM_TEMPLATE', None)
        app.config.setdefault('MULTIAUTH_LOGIN_ENDPOINT', 'login')
        app.config.setdefault('MULTIAUTH_LOGIN_URLS', ('/login/', '/login/<provider>'))
        app.config.setdefault('MULTIAUTH_SUCCESS_ENDPOINT', 'index')
        app.config.setdefault('MULTIAUTH_FAILURE_MESSAGE', 'Authentication failed: {error}')
        app.config.setdefault('MULTIAUTH_FAILURE_CATEGORY', 'error')

    def initialize(self, app=None):
        """Initializes the providers for the app.

        This is done automatically when necessary, but you can do so
        explicitly once your application's config is ready to get any
        initialization-time errors at a convenient time instead of
        whenever this is called implicitly.

        :param app: The flask application. If omitted, the current app
                    is used.
        """
        state = get_state(app, False)
        if state.initialized:
            return
        with state.app.app_context():
            self._create_login_rule()
            # Instantiate all the auth providers
            auth_providers = {}
            auth_provider_types = set()
            for name, settings in iteritems(current_app.config['MULTIAUTH_AUTH_PROVIDERS']):
                settings = settings.copy()
                cls = resolve_provider_type(AuthProvider, settings.pop('type'))
                if not cls.multi_instance and cls.type in auth_provider_types:
                    raise RuntimeError('Auth provider does not support multiple instances: ' + cls.type)
                auth_providers[name] = cls(self, name, settings)
                auth_provider_types.add(cls.type)
            state.auth_providers = ImmutableDict(auth_providers)
        state.initialized = True

    @property
    def auth_providers(self):
        """Returns a read-only dict ofwith the active auth providers"""
        return get_state().auth_providers

    def redirect_success(self):
        """Redirects to whatevr page should be displayed after login"""
        return redirect(self._get_next_url())

    def process_login(self, provider=None):
        """Handles the login process

        This needs to be registered in the Flask routing system and
        accept GET and POST requests on two URLs, one of them
        containing the ``<provider>`` placeholder. When executed with
        no provider, the login selector page will be shown unless there
        is only one provider available - in this case the page will
        immediately redirect to that provider.

        :param provider: The provider named used to log in.
        """
        if provider is None:
            return self._login_selector()

        try:
            provider = self.auth_providers[provider]
        except KeyError:
            raise NotFound('Provider does not exist')

        if provider.is_external:
            return self._login_external(provider)
        else:
            return self._login_form(provider)

    def handle_auth_info(self, auth_info):
        """Called after a successful authentication

        :param auth_info: An :class:`.AuthInfo` instance containing
                          data that can be used to uniquely identify
                          the user.
        """
        # TODO: pass auth into to linked user providers
        flash('Received AuthInfo: {}'.format(auth_info), 'success')

    def render_template(self, template_key, **kwargs):
        """Renders a template configured in the app config

        :param template_key: The template key to insert in the config
                             option name ``MULTIAUTH_*_TEMPLATE``
        :param kwargs: The variables passed to the template/
        """
        key = 'MULTIAUTH_{}_TEMPLATE'.format(template_key)
        template = current_app.config[key]
        if template is None:
            raise RuntimeError('Config option missing: ' + key)
        return render_template(template, **kwargs)

    def _create_login_rule(self):
        """Creates the login URL rule if necessary"""
        endpoint = current_app.config['MULTIAUTH_LOGIN_ENDPOINT']
        rules = current_app.config['MULTIAUTH_LOGIN_URLS']
        if not endpoint or not rules:
            return
        for rule in rules:
            current_app.add_url_rule(rule, endpoint, self.process_login, methods=('GET', 'POST'))

    def _set_next_url(self):
        """Saves the URL to redirect to after logging in."""
        next_url = request.args.get('next')
        if next_url is None:
            next_url = url_for(current_app.config['MULTIAUTH_SUCCESS_ENDPOINT'])
        session['multiauth_next_url'] = next_url

    def _get_next_url(self):
        """Returns the saved URL to redirect to after logging in.

        This only works once, as the saved URL is removed from the
        session afterwards.
        """
        try:
            return session.pop('multiauth_next_url')
        except KeyError:
            return url_for(current_app.config['MULTIAUTH_SUCCESS_ENDPOINT'])

    def _login_selector(self):
        """Shows the login method (auth provider) selector"""
        providers = self.auth_providers
        next_url = request.args.get('next')
        if len(providers) == 1:
            provider = next(iter(providers.values()))
            return redirect(url_for(current_app.config['MULTIAUTH_LOGIN_ENDPOINT'], provider=provider.name,
                                    next=next_url))
        else:
            return self.render_template('LOGIN_SELECTOR', providers=self.auth_providers.values(), next=next_url)

    def _login_external(self, provider):
        """Starts the external login process"""
        self._set_next_url()
        return provider.initiate_external_login()

    def _login_form(self, provider):
        """Starts the local form-based login process"""
        form = provider.login_form()
        if not form.is_submitted():
            self._set_next_url()
        if form.validate_on_submit():
            try:
                auth_info = provider.process_local_login(form.data)
            except AuthenticationFailed as e:
                flash(current_app.config['MULTIAUTH_FAILURE_MESSAGE'].format(error=text_type(e)),
                      current_app.config['MULTIAUTH_FAILURE_CATEGORY'])
            else:
                self.handle_auth_info(auth_info)
                return self.redirect_success()
        return self.render_template('LOGIN_FORM', form=form, provider=provider)


class _MultiAuthState(object):
    def __init__(self, multiauth, app):
        self.multiauth = multiauth
        self.app = app
        self.initialized = False
        self.auth_providers = {}

    def __repr__(self):
        return '<MultiAuthState({}, {})>'.format(self.multiauth, self.app)
