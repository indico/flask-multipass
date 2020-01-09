# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import absolute_import, unicode_literals

from werkzeug.local import LocalStack, LocalProxy

_ldap_ctx_stack = LocalStack()

#: Proxy to the current ldap connection and settings
current_ldap = LocalProxy(lambda: _ldap_ctx_stack.top)
