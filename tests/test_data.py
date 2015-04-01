# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import pytest

from flask_multiauth import AuthInfo


def test_authinfo():
    with pytest.raises(ValueError):
        AuthInfo(None)
    ai = AuthInfo(None, foo='bar')
    assert ai.data == {'foo': 'bar'}
