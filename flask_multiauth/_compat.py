# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

import sys

if sys.version_info[0] > 2:
    text_type = str
    string_types = str,

    def iteritems(arg, **kwargs):
        return iter(arg.items(**kwargs))
else:
    text_type = unicode
    string_types = basestring,

    def iteritems(arg, **kwargs):
        return iter(arg.iteritems(**kwargs))
