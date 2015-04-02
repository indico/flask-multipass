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
from flask_multiauth.user import UserProvider
from flask_multiauth.util import get_state, resolve_provider_type, get_canonical_provider_map


class MultiAuth(object):
    """Base class of the Flask-MultiAuth extension.

    :param app: The flask application. If omitted, use :meth:`init_app`
                to initialize the extension for you application.
    """

    def __init__(self, app=None):
        self.user_callback = None
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
        state = app.extensions['multiauth'] = _MultiAuthState(self, app)
        # TODO: write docs for the config (see flask-cache for a pretty example)
        app.config.setdefault('MULTIAUTH_AUTH_PROVIDERS', {})
        app.config.setdefault('MULTIAUTH_USER_PROVIDERS', {})
        app.config.setdefault('MULTIAUTH_PROVIDER_MAP', {})
        app.config.setdefault('MULTIAUTH_LOGIN_SELECTOR_TEMPLATE', None)
        app.config.setdefault('MULTIAUTH_LOGIN_FORM_TEMPLATE', None)
        app.config.setdefault('MULTIAUTH_LOGIN_ENDPOINT', 'login')
        app.config.setdefault('MULTIAUTH_LOGIN_URLS', ('/login/', '/login/<provider>'))
        app.config.setdefault('MULTIAUTH_SUCCESS_ENDPOINT', 'index')
        app.config.setdefault('MULTIAUTH_FAILURE_MESSAGE', 'Authentication failed: {error}')
        app.config.setdefault('MULTIAUTH_FAILURE_CATEGORY', 'error')
        app.config.setdefault('MULTIAUTH_ALL_MATCHING_USERS', False)
        with app.app_context():
            self._create_login_rule()
            state.auth_providers = ImmutableDict(self._create_providers('AUTH', AuthProvider))
            state.user_providers = ImmutableDict(self._create_providers('USER', UserProvider))
            state.provider_map = ImmutableDict(get_canonical_provider_map(current_app.config['MULTIAUTH_PROVIDER_MAP']))

    @property
    def auth_providers(self):
        """Returns a read-only dict of the active auth providers"""
        return get_state().auth_providers

    @property
    def user_providers(self):
        """Returns a read-only dict of the active user providers"""
        return get_state().user_providers

    @property
    def provider_map(self):
        """Returns a read-only mapping between auth and user providers."""
        return get_state().provider_map

    def redirect_success(self):
        """Redirects to whatever page should be displayed after login"""
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
        try:
            links = self.provider_map[auth_info.provider.name]
        except KeyError:
            raise Exception('No user providers configured for auth provider ' + auth_info.provider.name)
        users = []
        for link in links:
            provider = self.user_providers[link['user_provider']]
            mapping = link.get('mapping', {})
            user_info = provider.get_user_from_auth(auth_info.map(mapping))
            users.append(user_info)
            if not current_app.config['MULTIAUTH_ALL_MATCHING_USERS']:
                break
        if current_app.config['MULTIAUTH_ALL_MATCHING_USERS']:
            self.login_finished(users)
        else:
            self.login_finished(users[0] if users else None)

    def login_finished(self, user):
        """Called after the login process finished.

        This method invokes the function registered via
        :obj:`user_handler` with the same arguments.

        :param user: If ``MULTIAUTH_ALL_MATCHING_USERS`` is False, this
                     is a :class:`.UserInfo` or ``None`` if not user
                     was found.  If the setting is True, it is always a
                     list of the matching users (which is empty if no
                     users was found)
        """
        assert self.user_callback is not None, \
            'No user callback has been registered. Register one using ' \
            'Register one using the MultiAuth.user_handler decorator.'
        self.user_callback(user)

    def handle_auth_error(self, exc, redirect_to_login=False):
        """Handles an authentication failure

        :param exc: The exception indicating the error.
        :param redirect_to_login: Returns a redirect response to the
                                  login page.
        """
        flash(current_app.config['MULTIAUTH_FAILURE_MESSAGE'].format(error=text_type(exc)),
              current_app.config['MULTIAUTH_FAILURE_CATEGORY'])
        if redirect_to_login:
            return redirect(url_for(current_app.config['MULTIAUTH_LOGIN_ENDPOINT']))

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

    def user_handler(self, callback):
        """Registers the callback function that receives user information after login

        See :meth:`login_finished` for a description of the parameters.
        """
        self.user_callback = callback
        return callback

    def _create_providers(self, key, base):
        """Instantiates all providers

        :param key: The key to insert into the config option name
                    ``MULTIAUTH_*_PROVIDERS``
        :param base: The base class of the provider type.
        """
        providers = {}
        provider_types = set()
        for name, settings in iteritems(current_app.config['MULTIAUTH_{}_PROVIDERS'.format(key)]):
            settings = settings.copy()
            cls = resolve_provider_type(base, settings.pop('type'))
            if not cls.multi_instance and cls.type in provider_types:
                raise RuntimeError('Provider does not support multiple instances: ' + cls.type)
            providers[name] = cls(self, name, settings)
            provider_types.add(cls.type)
        return providers

    def _create_login_rule(self):
        """Creates the login URL rule if necessary"""
        endpoint = current_app.config['MULTIAUTH_LOGIN_ENDPOINT']
        rules = current_app.config['MULTIAUTH_LOGIN_URLS']
        if rules is None:
            return
        for rule in rules:
            current_app.add_url_rule(rule, endpoint, self.process_login, methods=('GET', 'POST'))

    def _set_next_url(self):
        """Saves the URL to redirect to after logging in."""
        next_url = request.args.get('next')
        if not next_url:
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
                self.handle_auth_error(e)
            else:
                self.handle_auth_info(auth_info)
                return self.redirect_success()
        return self.render_template('LOGIN_FORM', form=form, provider=provider)


class _MultiAuthState(object):
    def __init__(self, multiauth, app):
        self.multiauth = multiauth
        self.app = app
        self.auth_providers = {}
        self.user_providers = {}
        self.provider_map = {}

    def __repr__(self):
        return '<MultiAuthState({}, {})>'.format(self.multiauth, self.app)
