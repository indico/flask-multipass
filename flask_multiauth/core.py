# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask import current_app, render_template, request, url_for, session, redirect, flash
from werkzeug.datastructures import ImmutableDict
from werkzeug.exceptions import NotFound

from flask_multiauth._compat import iteritems, itervalues, text_type
from flask_multiauth.auth import AuthProvider
from flask_multiauth.exceptions import MultiAuthException, IdentityRetrievalFailed, GroupRetrievalFailed
from flask_multiauth.identity import IdentityProvider
from flask_multiauth.util import (get_state, resolve_provider_type, get_canonical_provider_map, validate_provider_map,
                                  get_provider_base)


class MultiAuth(object):
    """Base class of the Flask-MultiAuth extension.

    :param app: The flask application. If omitted, use :meth:`init_app`
                to initialize the extension for you application.
    """

    def __init__(self, app=None):
        self.identity_callback = None
        self.login_check_callback = None
        self.provider_registry = {AuthProvider: {}, IdentityProvider: {}}
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
        app.config.setdefault('MULTIAUTH_IDENTITY_PROVIDERS', {})
        app.config.setdefault('MULTIAUTH_PROVIDER_MAP', {})
        app.config.setdefault('MULTIAUTH_IDENTITY_INFO_KEYS', None)
        app.config.setdefault('MULTIAUTH_LOGIN_SELECTOR_TEMPLATE', None)
        app.config.setdefault('MULTIAUTH_LOGIN_FORM_TEMPLATE', None)
        app.config.setdefault('MULTIAUTH_LOGIN_ENDPOINT', 'login')
        app.config.setdefault('MULTIAUTH_LOGIN_URLS', ('/login/', '/login/<provider>'))
        app.config.setdefault('MULTIAUTH_SUCCESS_ENDPOINT', 'index')
        app.config.setdefault('MULTIAUTH_FAILURE_MESSAGE', 'Authentication failed: {error}')
        app.config.setdefault('MULTIAUTH_FAILURE_CATEGORY', 'error')
        app.config.setdefault('MULTIAUTH_ALL_MATCHING_IDENTITIES', False)
        app.config.setdefault('MULTIAUTH_REQUIRE_IDENTITY', True)
        with app.app_context():
            self._create_login_rule()
            state.auth_providers = ImmutableDict(self._create_providers('AUTH', AuthProvider))
            state.identity_providers = ImmutableDict(self._create_providers('IDENTITY', IdentityProvider))
            state.provider_map = ImmutableDict(get_canonical_provider_map(current_app.config['MULTIAUTH_PROVIDER_MAP']))
            validate_provider_map(state)

    @property
    def auth_providers(self):
        """Returns a read-only dict of the active auth providers"""
        return get_state().auth_providers

    @property
    def identity_providers(self):
        """Returns a read-only dict of the active identity providers"""
        return get_state().identity_providers

    @property
    def provider_map(self):
        """Returns a read-only mapping between auth and identity providers."""
        return get_state().provider_map

    def register_provider(self, cls, type_):
        """Registers a new provider type.

        This can be used to register a new provider type in the
        application without having to go through the entry point
        system.

        :param cls: The provider. Must be a subclass of either
                    :class:`.AuthProvider` or
                    :class:`.IdentityProvider`.
        :param type_: The type name of the provider used to reference
                      it in the configuration.
        """
        registry = self.provider_registry[get_provider_base(cls)]
        assert type_ not in registry, 'Provider is already registered: ' + cls.__name__
        registry[type_] = cls

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
        if self.login_check_callback and self.login_check_callback():
            self._set_next_url()
            return self.redirect_success()

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

    def logout(self):
        """Performs a provider-specific logout.

        This should be called by the application before clearing the
        session. If it returns a value that is not ``None``, it must
        be returned from your view function to Flask so a provider can
        for example redirect to an external logout page.

        :return: ``None`` or a Flask respnse
        """
        auth_provider_name = session['_multiauth_login_provider']
        auth_provider = self.auth_providers.get(auth_provider_name)
        if auth_provider:
            return auth_provider.process_logout()

    def handle_auth_info(self, auth_info):
        """Called after a successful authentication

        This method calls :meth:`login_finished` with the found
        identity.  If ``MULTIAUTH_ALL_MATCHING_IDENTITIES`` is set, it
        will pass a list of identities.  If ``MULTIAUTH_REQUIRE_IDENTITY``
        is set, :exc:`.IdentityRetrievalFailed` will be raised if no
        identities were found, otherwise ``None`` or and empty list
        will be passed.

        :param auth_info: An :class:`.AuthInfo` instance containing
                          data that can be used to retrieve the user's
                          unique identity.
        """
        links = self.provider_map[auth_info.provider.name]
        identities = []
        for link in links:
            provider = self.identity_providers[link['identity_provider']]
            mapping = link.get('mapping', {})
            identity_info = provider.get_identity_from_auth(auth_info.map(mapping))
            if identity_info is None:
                continue
            identities.append(identity_info)
            if not current_app.config['MULTIAUTH_ALL_MATCHING_IDENTITIES']:
                break
        if not identities and current_app.config['MULTIAUTH_REQUIRE_IDENTITY']:
            raise IdentityRetrievalFailed("No identity found")
        session['_multiauth_login_provider'] = auth_info.provider.name
        if current_app.config['MULTIAUTH_ALL_MATCHING_IDENTITIES']:
            return self.login_finished(identities)
        else:
            return self.login_finished(identities[0] if identities else None)

    def login_finished(self, identity_info):
        """Called after the login process finished.

        This method invokes the function registered via
        :obj:`identity_handler` with the same arguments.

        :param identity_info: An :class:`.IdentityInfo` instance or
                              a list of them
        """
        assert self.identity_callback is not None, \
            'No identity callback has been registered. Register one using ' \
            'Register one using the MultiAuth.identity_handler decorator.'
        return self.identity_callback(identity_info)

    def handle_auth_error(self, exc, redirect_to_login=False):
        """Handles an authentication failure

        :param exc: The exception indicating the error.
        :param redirect_to_login: Returns a redirect response to the
                                  login page.
        """
        session['multiauth_auth_failed'] = True
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

    def identity_handler(self, callback):
        """
        Registers the callback function that receives identity
        information after a successful login.

        If the callback returns a value, it is expected to be a valid
        return value for a Flask view function such as a redirect.
        In this case the target page should do whatever it needs to do
        (like showing an account creation form) and then use
        :meth:`redirect_success` to redirect to the destination page.

        See :meth:`login_finished` for a description of the parameters.
        """
        self.identity_callback = callback
        return callback

    def login_check(self, callback):
        """
        Registers the callback function used to determine if the user
        is already logged in.

        This is optional, but recommended, as it will avoid showing
        the login form to a user who is already logged in. When
        accessing the login page while being logged in, the user will
        be redirected to the same URL he'd be redirected to after a
        successful login.
        """
        self.login_check_callback = callback
        return callback

    def refresh_identity(self, identifier, multiauth_data):
        """Retrieves user identity information for an existing identity

        :param identifier: The `identifier` from :class:`.IdentityInfo`
        :param multiauth_data: The `multiauth_data` dict from
                               :class:`.IdentityInfo`
        :return: An :class:`.IdentityInfo` instance or ``None`` if the
                 identity does not exist anymore.
        """
        if multiauth_data is None:
            raise ValueError('This identity cannot be refreshed')
        provider_name = multiauth_data['_provider']
        try:
            provider = self.identity_providers[provider_name]
        except KeyError:
            raise IdentityRetrievalFailed('Provider does not exist: ' + provider_name)
        if not provider.supports_refresh:
            raise IdentityRetrievalFailed('Provider does not support refreshing: ' + provider_name)
        return provider.refresh_identity(identifier, multiauth_data)

    def search_identities(self, providers=None, exact=False, **criteria):
        """Searches user identities matching certain criteria

        :param providers: A list of providers to search in. If not
                          specified, all providers are searched.
        :param exact: If criteria need to match exactly, i.e. no
                      substring matches are performed.
        :param criteria: The criteria to search for.
        :return: An iterable of matching user identities.
        """
        for provider in itervalues(self.identity_providers):
            if providers is not None and provider.name not in providers:
                continue
            if not provider.supports_search:
                continue
            for identity_info in provider.search_identities(provider.map_search_criteria(criteria), exact=exact):
                yield identity_info

    def get_group(self, provider, name):
        """Returns a specific group

        :param provider: The name of the provider containing the group.
        :param name: The name of the group.
        :return: An instance of a :class:`.Group` subclass.
        """
        try:
            provider = self.identity_providers[provider]
        except KeyError:
            raise GroupRetrievalFailed('Provider does not exist: ' + provider)
        return provider.get_group(name)

    def search_groups(self, name, providers=None, exact=False):
        """Searches groups by name

        :param name: The name to search for.
        :param providers: A list of providers to search in. If not
                          specified, all providers are searched.
        :param exact: If the name needs to match exactly, i.e. no
                      substring matches are performed.
        :return: An iterable of matching groups.
        """
        for provider in itervalues(self.identity_providers):
            if providers is not None and provider.name not in providers:
                continue
            if not provider.supports_groups:
                continue
            for group in provider.search_groups(name, exact=exact):
                yield group

    def is_identity_in_group(self, provider, identity_identifier, group_name):
        """Checks if a user identity is in a group

        :param provider: The name of the provider containing the group.
        :param identity_identifier: The identifier of the user.
        :param group_name: The name of the group.
        """
        group = self.get_group(provider, group_name)
        return identity_identifier in group

    def _create_providers(self, key, base):
        """Instantiates all providers

        :param key: The key to insert into the config option name
                    ``MULTIAUTH_*_PROVIDERS``
        :param base: The base class of the provider type.
        """
        registry = self.provider_registry[AuthProvider if key == 'AUTH' else IdentityProvider]
        providers = {}
        provider_classes = set()
        for name, settings in iteritems(current_app.config['MULTIAUTH_{}_PROVIDERS'.format(key)]):
            settings = settings.copy()
            cls = resolve_provider_type(base, settings.pop('type'), registry)
            if not cls.multi_instance and cls in provider_classes:
                raise RuntimeError('Provider does not support multiple instances: ' + cls.__name__)
            providers[name] = cls(self, name, settings)
            provider_classes.add(cls)
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
        auth_failed = session.pop('multiauth_auth_failed', False)
        login_endpoint = current_app.config['MULTIAUTH_LOGIN_ENDPOINT']
        if not auth_failed and len(providers) == 1:
            provider = next(iter(providers.values()))
            return redirect(url_for(login_endpoint, provider=provider.name, next=next_url))
        else:
            return self.render_template('LOGIN_SELECTOR', providers=self.auth_providers.values(), next=next_url,
                                        auth_failed=auth_failed, login_endpoint=login_endpoint)

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
                rv = self.handle_auth_info(auth_info)
            except MultiAuthException as e:
                self.handle_auth_error(e)
            else:
                return rv or self.redirect_success()
        return self.render_template('LOGIN_FORM', form=form, provider=provider)


class _MultiAuthState(object):
    def __init__(self, multiauth, app):
        self.multiauth = multiauth
        self.app = app
        self.auth_providers = {}
        self.identity_providers = {}
        self.provider_map = {}

    def __repr__(self):
        return '<MultiAuthState({}, {})>'.format(self.multiauth, self.app)
