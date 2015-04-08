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
.. autoclass:: flask_multiauth.providers.oauth.OAuthAuthProvider
   :members:
.. autoclass:: flask_multiauth.providers.static.StaticAuthProvider
   :members:
.. autoclass:: flask_multiauth.providers.sqlalchemy.SQLAlchemyAuthProviderBase
   :members:


User Providers
--------------
.. automodule:: flask_multiauth.user
   :members:
.. autoclass:: flask_multiauth.providers.oauth.OAuthUserProvider
   :members:
.. autoclass:: flask_multiauth.providers.static.StaticUserProvider
   :members:
.. autoclass:: flask_multiauth.providers.sqlalchemy.SQLAlchemyUserProviderBase
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
