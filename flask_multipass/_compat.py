# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

import operator
import sys


if sys.version_info[0] > 2:
    PY2 = False
    bytes_type = bytes
    text_type = str
    string_types = str,
    viewkeys = operator.methodcaller('keys')

    def iteritems(arg, **kwargs):
        return iter(arg.items(**kwargs))

    def itervalues(arg, **kwargs):
        return iter(arg.values(**kwargs))
else:
    PY2 = True
    bytes_type = str
    text_type = unicode
    string_types = basestring,
    viewkeys = operator.methodcaller('viewkeys')

    def iteritems(arg, **kwargs):
        return iter(arg.iteritems(**kwargs))

    def itervalues(arg, **kwargs):
        return arg.itervalues(**kwargs)


# taken from six - https://pythonhosted.org/six/
def add_metaclass(metaclass):
    """Class decorator for creating a class with a metaclass."""
    def wrapper(cls):
        orig_vars = cls.__dict__.copy()
        slots = orig_vars.get('__slots__')
        if slots is not None:
            if isinstance(slots, str):
                slots = [slots]
            for slots_var in slots:
                orig_vars.pop(slots_var)
        orig_vars.pop('__dict__', None)
        orig_vars.pop('__weakref__', None)
        return metaclass(cls.__name__, cls.__bases__, orig_vars)
    return wrapper


try:
    from flask_wtf import FlaskForm
except ImportError:
    try:
        from flask_wtf import Form as FlaskForm
    except ImportError:
        FlaskForm = None
