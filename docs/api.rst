API
===


Core
----
.. automodule:: flask_multipass.core
   :members:

.. _auth_providers:

Authentication Providers
------------------------
.. automodule:: flask_multipass.auth
   :members:
.. autoclass:: flask_multipass.providers.ldap.LDAPAuthProvider
   :members:
.. autoclass:: flask_multipass.providers.authlib.AuthlibAuthProvider
   :members:
.. autoclass:: flask_multipass.providers.saml.SAMLAuthProvider
   :members:
.. autoclass:: flask_multipass.providers.static.StaticAuthProvider
   :members:
.. autoclass:: flask_multipass.providers.shibboleth.ShibbolethAuthProvider
   :members:
.. autoclass:: flask_multipass.providers.sqlalchemy.SQLAlchemyAuthProviderBase
   :members:

.. _identity_providers:

Identity Providers
-----------------------
.. automodule:: flask_multipass.identity
   :members:
.. autoclass:: flask_multipass.providers.ldap.LDAPIdentityProvider
   :members:
.. autoclass:: flask_multipass.providers.authlib.AuthlibIdentityProvider
   :members:
.. autoclass:: flask_multipass.providers.saml.SAMLIdentityProvider
   :members:
.. autoclass:: flask_multipass.providers.static.StaticIdentityProvider
   :members:
.. autoclass:: flask_multipass.providers.shibboleth.ShibbolethIdentityProvider
   :members:
.. autoclass:: flask_multipass.providers.sqlalchemy.SQLAlchemyIdentityProviderBase
   :members:


Data Structures
---------------
.. automodule:: flask_multipass.data
   :members:


Groups
------
.. automodule:: flask_multipass.group
   :members:


Utils
-----
.. automodule:: flask_multipass.util
   :members:
   :exclude-members: expand_provider_links, get_state, classproperty, validate_provider_map


Exceptions
----------
.. automodule:: flask_multipass.exceptions
   :members:
