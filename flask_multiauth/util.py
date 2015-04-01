# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from inspect import isclass
from pkg_resources import iter_entry_points

from flask import current_app


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
