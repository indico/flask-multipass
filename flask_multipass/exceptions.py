# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals


class MultipassException(Exception):
    """Base class for Multipass exceptions"""

    def __init__(self, message=None, details=None, provider=None):
        args = (message,) if message else ()
        Exception.__init__(self, *args)
        self.details = details
        self.provider = provider


class AuthenticationFailed(MultipassException):
    """
    Indicates an authentication failure that was caused by the user,
    e.g. by entering the wrong credentials or not authorizing the
    application
    """


class NoSuchUser(AuthenticationFailed):
    """Indicates a user does not exist when attempting to authenticate."""

    def __init__(self, details=None, provider=None):
        AuthenticationFailed.__init__(self, 'No such user', details=details, provider=provider)


class InvalidCredentials(AuthenticationFailed):
    """Indicates a failure to authenticate using the given credentials."""

    def __init__(self, details=None, provider=None):
        AuthenticationFailed.__init__(self, 'Invalid credentials', details=details, provider=provider)


class IdentityRetrievalFailed(MultipassException):
    """Indicates a failure while retrieving identity information"""


class GroupRetrievalFailed(MultipassException):
    """Indicates a failure while retrieving group information"""
