# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import sys

import flask_multiauth


def pytest_configure(config):
    # Disable the support attr checks while testing
    attrs = ('AuthProvider', 'Group', 'IdentityProvider')
    for attr in attrs:
        getattr(flask_multiauth, attr).__support_attrs__ = {}


collect_ignore = []
if sys.version_info[0] > 2:
    collect_ignore.append('providers/ldap/')
