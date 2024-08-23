# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from .auth import AuthProvider
from .core import Multipass
from .data import AuthInfo, IdentityInfo
from .exceptions import (AuthenticationFailed, GroupRetrievalFailed, IdentityRetrievalFailed, InvalidCredentials,
                         MultipassException, NoSuchUser)
from .group import Group
from .identity import IdentityProvider


__all__ = ('Multipass', 'AuthProvider', 'IdentityProvider', 'AuthInfo', 'IdentityInfo', 'Group', 'MultipassException',
           'AuthenticationFailed', 'IdentityRetrievalFailed', 'GroupRetrievalFailed', 'NoSuchUser',
           'InvalidCredentials')


def __getattr__(name):
    if name == '__version__':
        import importlib.metadata
        import warnings

        warnings.warn(
            'The `__version__` attribute is deprecated. Use feature detection or'
            " `importlib.metadata.version('flask-multipass')` instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return importlib.metadata.version('flask-multipass')

    raise AttributeError(name)
