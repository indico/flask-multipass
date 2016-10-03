# This file is part of Flask-Multipass.
# Copyright (C) 2015 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

import ast
import re
import sys

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


with open('flask_multipass/__init__.py', 'rb') as f:
    version_line = re.search(r'__version__\s+=\s+(.*)', f.read().decode('utf-8')).group(1)
    version = str(ast.literal_eval(version_line))


setup(
    name='Flask-Multipass',
    version=version,
    url='https://github.com/indico/flask-multipass',
    license='BSD',
    author='Indico Team',
    author_email='indico-team@cern.ch',
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask>=0.10.1',  # TODO: check the oldest version we can work with
        'blinker'
    ],
    tests_require=['pytest', 'pytest-cov', 'pytest-mock'],
    cmdclass={'test': PyTest},
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5'
    ],
    entry_points={
        'flask_multipass.auth_providers': {
            'ldap = flask_multipass.providers.ldap:LDAPAuthProvider',
            'oauth = flask_multipass.providers.oauth:OAuthAuthProvider',
            'shibboleth = flask_multipass.providers.shibboleth:ShibbolethAuthProvider',
            'static = flask_multipass.providers.static:StaticAuthProvider'
        },
        'flask_multipass.identity_providers': {
            'ldap = flask_multipass.providers.ldap:LDAPIdentityProvider',
            'oauth = flask_multipass.providers.oauth:OAuthIdentityProvider',
            'shibboleth = flask_multipass.providers.shibboleth:ShibbolethIdentityProvider',
            'static = flask_multipass.providers.static:StaticIdentityProvider'
        }
    }
)
