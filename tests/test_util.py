# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask_multiauth.util import classproperty


def test_classproperty():
    class Foo(object):
        @classproperty
        @classmethod
        def bar(cls):
            return 'foobar'

    class B(Foo):
        pass

    class C(Foo):
        pass

    assert Foo.bar == 'foobar'
    assert B.bar == 'foobar'
    assert C.bar == 'foobar'
    B.bar = 'moo'
    assert Foo.bar == 'foobar'
    assert B.bar == 'moo'
    assert C.bar == 'foobar'
    Foo.bar = 'asdf'
    assert Foo.bar == 'asdf'
    assert B.bar == 'moo'
    assert C.bar == 'asdf'
    inst = Foo()
    assert inst.bar == 'asdf'
    inst.bar = 'xyz'
    assert inst.bar == 'xyz'
    assert Foo.bar == 'asdf'
