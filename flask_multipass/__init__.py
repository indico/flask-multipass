# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from .core import Multipass
from .auth import AuthProvider
from .data import AuthInfo, IdentityInfo
from .exceptions import (MultipassException, AuthenticationFailed, IdentityRetrievalFailed, GroupRetrievalFailed,
                         NoSuchUser, InvalidCredentials)
from .group import Group
from .identity import IdentityProvider

__version__ = '0.3.1'
__all__ = ('Multipass', 'AuthProvider', 'IdentityProvider', 'AuthInfo', 'IdentityInfo', 'Group', 'MultipassException',
           'AuthenticationFailed', 'IdentityRetrievalFailed', 'GroupRetrievalFailed', 'NoSuchUser',
           'InvalidCredentials')
