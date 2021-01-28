# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

import ast
import re

from setuptools import setup


# TODO: get rid of this and define it in setup.cfg once we are py3-only;
# see the comment in that file for an explanation
with open('flask_multipass/__init__.py', 'rb') as f:
    version_line = re.search(r'__version__\s+=\s+(.*)', f.read().decode('utf-8')).group(1)
    version = str(ast.literal_eval(version_line))


setup(
    name='Flask-Multipass',
    version=version,
)
