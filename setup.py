# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

import ast
import re
import sys

from setuptools import setup, find_packages


with open('flask_multipass/__init__.py', 'rb') as f:
    version_line = re.search(r'__version__\s+=\s+(.*)', f.read().decode('utf-8')).group(1)
    version = str(ast.literal_eval(version_line))


needs_pytest = {'pytest', 'test', 'ptr'}.intersection(sys.argv)
pytest_runner = ['pytest-runner'] if needs_pytest else []


setup(
    name='Flask-Multipass',
    version=version,
    url='https://github.com/indico/flask-multipass',
    license='BSD',
    author='Indico Team',
    author_email='indico-team@cern.ch',
    packages=find_packages(exclude=['tests']),
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'Flask>=0.10.1',  # TODO: check the oldest version we can work with
        'blinker'
    ],
    setup_requires=pytest_runner,
    tests_require=['pytest', 'pytest-cov', 'pytest-mock'],
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
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
