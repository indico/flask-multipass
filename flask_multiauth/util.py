# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from functools import wraps
from inspect import isclass
from pkg_resources import iter_entry_points

from flask import current_app

from flask_multiauth._compat import iteritems, string_types
from flask_multiauth.exceptions import AuthenticationFailed


def get_canonical_provider_map(provider_map):
    """Converts the configured provider map to a canonical form"""
    canonical = {}
    for auth_provider_name, user_providers in iteritems(provider_map):
        if not isinstance(user_providers, (list, tuple, set)):
            user_providers = [user_providers]
        user_providers = tuple({'user_provider': p} if isinstance(p, string_types) else p for p in user_providers)
        canonical[auth_provider_name] = user_providers
    return canonical


def get_state(app=None, allow_uninitialized=False):
    """Gets the application-specific multiauth data.

    :param app: The Flask application. Defaults to the current app.
    :param allow_uninitialized: If an uninitialized state is allowed.
                                This is used internally so
                                :meth:`.MultiAuth.initialize` can make
                                use of this function.
    :rtype: flask_multiauth.core._MultiAuthState
    """
    if app is None:
        app = current_app
    assert 'multiauth' in app.extensions, \
        'The multiauth extension was not registered to the current application. ' \
        'Please make sure to call init_app() first.'
    state = app.extensions['multiauth']
    if not allow_uninitialized:
        assert state.initialized, \
            'The multiauth extension was not initialized for the current application. ' \
            'Please make sure to call initialize() first.'
    return state


def login_view(func):
    """Decorates a Flask view function as an authentication view.

    This catches auth-related exceptions and flashes a message and
    redirects back to the login page.
    """
    @wraps(func)
    def decorator(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except AuthenticationFailed as e:
            return get_state().multiauth.handle_auth_error(e, True)

    return decorator


def map_data(data, mapping):
    """Creates a dict with a fixed set of keys based on a mapping.

    :param data: A dict containing data.
    :param mapping: A dict containing the mapping between the `data`
                    dict and the result dict. Each key in the dict will
                    be used as a key in the returned dict and each
                    value will be used as the key to get the value from
                    `data`.
    :return: A dict that has the same keys as `mapping` and the values
             from `data`.
    """
    return {target_key: data.get(source_key) for target_key, source_key in iteritems(mapping)}


def resolve_provider_type(base, type_):
    """Resolves a provider type to its class

    :param base: The base class of the provider
    :param type_: The type of the provider. Can be a subclass of
                  `base` or the identifier of a registered type.
    :return: The type's class, which is a subclass of `base`.
    """
    if isclass(type_):
        if not issubclass(type_, base):
            raise TypeError('Received a class {} which is not a subclass of {}'.format(type_, base))
        return type_

    entry_points = list(iter_entry_points(base._entry_point, type_))
    if not entry_points:
        raise ValueError('Unknown type: ' + type_)
    elif len(entry_points) != 1:
        raise RuntimeError('Type {} is not unique. Defined in {}'.format(
            type_, ', '.join(ep.module_name for ep in entry_points)))
    entry_point = entry_points[0]
    cls = entry_point.load()
    if not issubclass(cls, base):
        raise TypeError('Found a class {} which is not a subclass of {}'.format(cls, base))
    return cls


class classproperty(property):
    """Like a :class:`property`, but for a class

    Usage::

        class Foo(object):
            @classproperty
            @classmethod
            def foo(cls):
                return 'bar'
    """
    def __get__(self, obj, type=None):
        return self.fget.__get__(None, type)()
