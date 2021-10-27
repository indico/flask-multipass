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


__version__ = '0.4.4'
__all__ = ('Multipass', 'AuthProvider', 'IdentityProvider', 'AuthInfo', 'IdentityInfo', 'Group', 'MultipassException',
           'AuthenticationFailed', 'IdentityRetrievalFailed', 'GroupRetrievalFailed', 'NoSuchUser',
           'InvalidCredentials')
