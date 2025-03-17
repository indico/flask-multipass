# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

class MultipassException(Exception):
    """Base class for Multipass exceptions."""

    def __init__(self, message=None, details=None, provider=None):
        args = (message,) if message else ()
        Exception.__init__(self, *args)
        self.details = details
        self.provider = provider


class AuthenticationFailed(MultipassException):
    """
    Indicates an authentication failure that was caused by the user,
    e.g. by entering the wrong credentials or not authorizing the
    application.
    """


class NoSuchUser(AuthenticationFailed):
    """Indicates a user does not exist when attempting to authenticate."""

    def __init__(self, message='No such user', *, details=None, provider=None, identifier=None):
        AuthenticationFailed.__init__(self, message, details=details, provider=provider)
        self.identifier = identifier


class InvalidCredentials(AuthenticationFailed):
    """Indicates a failure to authenticate using the given credentials."""

    def __init__(self, message='Invalid credentials', *, details=None, provider=None, identifier=None):
        AuthenticationFailed.__init__(self, message, details=details, provider=provider)
        self.identifier = identifier


class IdentityRetrievalFailed(MultipassException):
    """Indicates a failure while retrieving identity information."""


class GroupRetrievalFailed(MultipassException):
    """Indicates a failure while retrieving group information."""
