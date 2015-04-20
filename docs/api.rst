API
===


Core
----
.. automodule:: flask_multiauth.core
   :members:


Authentication Providers
------------------------
.. automodule:: flask_multiauth.auth
   :members:
.. autoclass:: flask_multiauth.providers.ldap.LDAPAuthProvider
   :members:
.. autoclass:: flask_multiauth.providers.oauth.OAuthAuthProvider
   :members:
.. autoclass:: flask_multiauth.providers.static.StaticAuthProvider
   :members:
.. autoclass:: flask_multiauth.providers.shibboleth.ShibbolethAuthProvider
   :members:
.. autoclass:: flask_multiauth.providers.sqlalchemy.SQLAlchemyAuthProviderBase
   :members:


User Identity Providers
-----------------------
.. automodule:: flask_multiauth.identity
   :members:
.. autoclass:: flask_multiauth.providers.ldap.LDAPIdentityProvider
   :members:
.. autoclass:: flask_multiauth.providers.oauth.OAuthIdentityProvider
   :members:
.. autoclass:: flask_multiauth.providers.static.StaticIdentityProvider
   :members:
.. autoclass:: flask_multiauth.providers.shibboleth.ShibbolethIdentityProvider
   :members:
.. autoclass:: flask_multiauth.providers.sqlalchemy.SQLAlchemyIdentityProviderBase
   :members:


Data Structures
---------------
.. automodule:: flask_multiauth.data
   :members:


Groups
------
.. automodule:: flask_multiauth.group
   :members:


Utils
-----
.. automodule:: flask_multiauth.util
   :members:
   :exclude-members: expand_provider_links, get_state, classproperty, validate_provider_map


Exceptions
----------
.. automodule:: flask_multiauth.exceptions
   :members:
