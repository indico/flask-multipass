# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import absolute_import, unicode_literals

from flask_multipass.exceptions import MultipassException


class LDAPException(MultipassException):
    """Base class for Multipass LDAP exceptions"""


class LDAPServerError(LDAPException):
    """Indicates the LDAP server had an unexpected behavior"""
