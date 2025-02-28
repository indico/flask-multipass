# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

import sys
from functools import wraps
from importlib.metadata import entry_points as importlib_entry_points
from inspect import getmro, isclass

from flask import current_app

from flask_multipass.exceptions import MultipassException


def convert_app_data(app_data, mapping, key_filter=None):
    """Converts data coming from the application to be used by the provider.

    :param app_data: dict -- Data coming from the application.
    :param mapping: dict -- Mapping between keys used to define the data
                    in the application and those used by the provider.
    :param key_filter: list -- Keys to be exclusively considered. If
                       ``None``, all items will be returned.
    :return: dict -- containing the values of `app_data` mapped to the
             keys of the provider as defined in the `mapping` and
             filtered out by `key_filter`.
    """
    if key_filter:
        key_filter = set(key_filter)
        app_data = {k: v for k, v in app_data.items() if k in key_filter}
    return {mapping.get(key, key): value for key, value in app_data.items()}


def convert_provider_data(provider_data, mapping, key_filter=None):
    """Converts data coming from the provider to be used by the application.

    The result will have all the keys listed in `keys` with values
    coming either from `data` (using the key mapping defined in
    `mapping`) or ``None`` in case the key is not present. If
    `key_filter` is ``None``, all keys from `provider_data` will be used
    unless they are mapped to a different key in `mapping`.

    :param provider_data: dict -- Data coming from the provider.
    :param mapping: dict -- Mapping between keys used to define the data
                    in the provider and those used by the application.
                    All application keys will be present in the return
                    value, defaulting to ``None``.
    :param key_filter: list -- Keys to be exclusively considered. If
                       ``None``, all items will be returned. Keys not
                       present in the mapped data, will have a value of
                       ``None``.
    :return: dict -- containing the values of `app_data` mapped to the
             keys of the application as defined in the `mapping` and
             filtered out by `key_filter`.
    """
    provider_keys = set(mapping.values())
    result = {key: value for key, value in provider_data.items() if key not in provider_keys}
    result.update((app_key, provider_data.get(provider_key)) for app_key, provider_key in mapping.items())
    if key_filter is not None:
        key_filter = set(key_filter)
        result = {key: value for key, value in result.items() if key in key_filter}
        result.update(dict.fromkeys(key_filter - set(result)))
    return result


def get_canonical_provider_map(provider_map):
    """Converts the configured provider map to a canonical form."""
    canonical = {}
    for auth_provider_name, identity_providers in provider_map.items():
        if not isinstance(identity_providers, (list, tuple, set)):
            identity_providers = [identity_providers]
        identity_providers = tuple({'identity_provider': p} if isinstance(p, str) else p for p in identity_providers)
        canonical[auth_provider_name] = identity_providers
    return canonical


def get_state(app=None):
    """Gets the application-specific multipass data.

    :param app: The Flask application. Defaults to the current app.
    :rtype: flask_multipass.core._MultipassState
    """
    if app is None:
        app = current_app
    assert 'multipass' in app.extensions, (
        'The multipass extension was not registered to the current application. '
        'Please make sure to call init_app() first.'
    )
    return app.extensions['multipass']


def get_provider_base(cls):
    """Returns the base class of a provider class.

    :param cls: A subclass of either :class:`.AuthProvider` or
                :class:`.IdentityProvider`.
    :return: :class:`.AuthProvider` or :class:`.IdentityProvider`
    """
    from flask_multipass.auth import AuthProvider
    from flask_multipass.identity import IdentityProvider
    if issubclass(cls, AuthProvider) and issubclass(cls, IdentityProvider):
        raise TypeError('Class inherits from both AuthProvider and IdentityProvider: ' + cls.__name__)
    elif issubclass(cls, AuthProvider):
        return AuthProvider
    elif issubclass(cls, IdentityProvider):
        return IdentityProvider
    else:
        raise TypeError('Class is neither an auth nor an identity provider: ' + cls.__name__)


def login_view(func):
    """Decorates a Flask view function as an authentication view.

    This catches multipass-related exceptions and flashes a message and
    redirects back to the login page.
    """
    @wraps(func)
    def decorator(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except MultipassException as e:
            return get_state().multipass.handle_auth_error(e, True)

    return decorator


def resolve_provider_type(base, type_, registry=None):
    """Resolves a provider type to its class.

    :param base: The base class of the provider
    :param type_: The type of the provider. Can be a subclass of
                  `base` or the identifier of a registered type.
    :param registry: A dict containing registered providers. This
                     complements the entrypoint-based lookup. Any
                     provider type defined in this dict takes priority
                     over an entrypoint-based one with the same name.
    :return: The type's class, which is a subclass of `base`.
    """
    if isclass(type_):
        if not issubclass(type_, base):
            raise TypeError(f'Received a class {type_} which is not a subclass of {base}')
        return type_

    if registry is not None and type_ in registry:
        cls = registry[type_]
    else:
        if sys.version_info < (3, 10):
            entry_points = {ep for ep in importlib_entry_points().get(base._entry_point, []) if ep.name == type_}
        else:
            entry_points = importlib_entry_points(group=base._entry_point, name=type_)
        if not entry_points:
            raise ValueError('Unknown type: ' + type_)
        elif len(entry_points) != 1:
            defs = ', '.join(ep.module for ep in entry_points)
            raise RuntimeError(f'Type {type_} is not unique. Defined in {defs}')
        entry_point = list(entry_points)[0]
        cls = entry_point.load()
    if not issubclass(cls, base):
        raise TypeError(f'Found a class {cls} which is not a subclass of {base}')
    return cls


def validate_provider_map(state):
    """Validates the provider map.

    :param state: The :class:`._MultipassState` instance
    """
    invalid_keys = state.auth_providers.keys() - state.provider_map.keys()
    if invalid_keys:
        raise ValueError('Auth providers not linked to identity providers: ' + ', '.join(invalid_keys))
    targeted_providers = {p['identity_provider'] for providers in state.provider_map.values() for p in providers}
    invalid_keys = targeted_providers - state.identity_providers.keys()
    if invalid_keys:
        raise ValueError('Broken identity provider links: ' + ', '.join(invalid_keys))


class classproperty(property):  # noqa: N801
    """Like a :class:`property`, but for a class.

    Usage::

        class Foo:
            @classproperty
            @classmethod
            def foo(cls):
                return 'bar'
    """

    def __get__(self, obj, type=None):
        return self.fget.__get__(None, type)()


class SupportsMeta(type):
    """
    Metaclass that requires/prohibits methods to be overridden
    depending on class attributes.

    The class using this metaclass must have a `__support_attrs__`
    attribute containing a dict mapping attribute names to method
    names (or lists of method names) which must be overridden if the
    attribute is True and may not mbe overridden if it isn't.

    Instead of a string key the dict may also contain a tuple returned
    from :meth:`callable`.
    """

    def __new__(mcs, name, bases, dct):
        cls = type.__new__(mcs, name, bases, dct)
        base = next((x for x in reversed(getmro(cls)) if type(x) is mcs and x is not cls), None)
        if base is None:
            return cls
        for attr, methods in base.__support_attrs__.items():
            if isinstance(methods, str):
                methods = (methods,)
            if isinstance(attr, tuple):
                supported = attr[0](cls)
                message = attr[1]
            else:
                supported = getattr(cls, attr, getattr(base, attr))
                message = f'{attr} is True'
            for method in methods:
                is_overridden = (getattr(base, method) != getattr(cls, method))
                if not supported and is_overridden:
                    raise TypeError(f'{name} cannot override {method} unless {message}')
                elif supported and not is_overridden:
                    raise TypeError(f'{name} must override {method} if {message}')
        return cls

    @staticmethod
    def callable(func, message):
        """Returns an object suitable for more complex.

        :param func: A callable that is invoked with the dict of the
                     newly created object
        :param message: The message to show in case of a failure.
        """
        return func, message
