# This file is part of Flask-PluginEngine.
# Copyright (C) 2014 CERN
#
# Flask-PluginEngine is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from werkzeug.local import LocalStack, LocalProxy

_ldap_ctx_stack = LocalStack()

#: Proxy to the current ldap connection and settings
current_ldap = LocalProxy(lambda: _ldap_ctx_stack.top)
