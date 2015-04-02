# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from .core import MultiAuth
from .auth import AuthProvider
from .data import AuthInfo
from .exceptions import AuthenticationFailed
from .user import UserProvider

__version__ = '0.0.dev0'
__all__ = ('MultiAuth', 'AuthProvider', 'UserProvider', 'AuthInfo', 'AuthenticationFailed')
