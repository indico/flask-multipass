Changelog
=========

Version 0.3.1
-------------

- Add ``search_identities_ex`` which allows more a flexible search with the option
  to specify the max number of results to return while also returning the total number
  of found identities.

Version 0.3
-----------

- **Breaking change:** Replace ``oauth`` provider with ``authlib``.
- **Breaking change:** Drop support for Python 3.4 and 3.5.
- The new authlib provider supports OIDC (OpenID-Connect) in addition to regular OAuth.
- Make ``ldap`` provider compatible with Python 3.

Version 0.2
-----------

- Add option to get all groups for an identity.

Version 0.1
-----------

- Initial release
