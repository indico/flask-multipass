# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals


class MultiAuthException(Exception):
    """Base class for MultiAuth exceptions"""


class AuthenticationFailed(MultiAuthException):
    """
    Indicates an authentication failure that was caused by the user,
    e.g. by entering the wrong credentials or not authorizing the
    application
    """


class UserRetrievalFailed(MultiAuthException):
    """Indicates a failure while retrieving user information"""


class GroupRetrievalFailed(MultiAuthException):
    """Indicates a failure while retrieving group information"""
