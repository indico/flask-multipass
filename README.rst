Flask-Multipass
===============

.. image:: https://raw.githubusercontent.com/indico/flask-multipass/master/artwork/flask-multipass.png

.. image:: https://readthedocs.org/projects/flask-multipass/badge/?version=latest
    :target: https://flask-multipass.readthedocs.org/
.. image:: https://github.com/indico/flask-multipass/workflows/Tests/badge.svg
    :target: https://github.com/indico/flask-multipass/actions

Flask-Multipass provides Flask with a user authentication/identity
system which can use different backends (such as local users,
LDAP and OAuth) simultaneously.

It was developed at CERN and is currently used in production by `Indico <https://github.com/indico/indico>`_.

There are bult-in authentication and identity providers for:

 * `Static (hardcoded) credentials <https://github.com/indico/flask-multipass/blob/master/flask_multipass/providers/static.py>`_
 * `Local (SQLAlchemy DB) authentication <https://github.com/indico/flask-multipass/blob/master/flask_multipass/providers/sqlalchemy.py>`_
 * `Authlib (OAuth/OIDC) <https://github.com/indico/flask-multipass/blob/master/flask_multipass/providers/authlib.py>`_
 * `SAML <https://github.com/indico/flask-multipass/blob/master/flask_multipass/providers/saml.py>`_
 * `Shibboleth <https://github.com/indico/flask-multipass/blob/master/flask_multipass/providers/shibboleth.py>`_
 * `LDAP <https://github.com/indico/flask-multipass/blob/master/flask_multipass/providers/ldap/providers.py>`_

Those can be used simultaneously and interchangeably (e.g. authenticate with OAuth and search users with LDAP).

Documentation is available at https://flask-multipass.readthedocs.org
