API
===


Core
----
.. automodule:: flask_multipass.core
   :members:


Authentication Providers
------------------------
.. automodule:: flask_multipass.auth
   :members:
.. autoclass:: flask_multipass.providers.ldap.LDAPAuthProvider
   :members:
.. autoclass:: flask_multipass.providers.oauth.OAuthAuthProvider
   :members:
.. autoclass:: flask_multipass.providers.static.StaticAuthProvider
   :members:
.. autoclass:: flask_multipass.providers.shibboleth.ShibbolethAuthProvider
   :members:
.. autoclass:: flask_multipass.providers.sqlalchemy.SQLAlchemyAuthProviderBase
   :members:


User Identity Providers
-----------------------
.. automodule:: flask_multipass.identity
   :members:
.. autoclass:: flask_multipass.providers.ldap.LDAPIdentityProvider
   :members:
.. autoclass:: flask_multipass.providers.oauth.OAuthIdentityProvider
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
