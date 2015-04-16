# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from flask_multiauth.exceptions import MultiAuthException


class LDAPException(MultiAuthException):
    """Base class for MultiAuth LDAP exceptions"""


class LDAPServerError(LDAPException):
    """Indicates the LDAP server had an unexpected behavior"""
