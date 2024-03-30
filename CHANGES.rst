Changelog
=========

Version 0.5.4
-------------

- Skip LDAP users that do not have the specified ``uid`` attribute set instead
  of failing with an error

Version 0.5.3
-------------

- Skip LDAP group members that do not have the specified ``uid`` attribute set instead
  of failing with an error

Version 0.5.2
-------------

- Add ``ldap_or_authinfo`` identity provider which behaves exactly like the ``ldap``
  provider, but if the user cannot be found in LDAP, it falls back to the data
  from the auth provider (typically shibboleth)

Version 0.5.1
-------------

- Fix compatibility with Python 3.8 and 3.9

Version 0.5
-----------

- Drop support for Python 3.7 and older (3.7 is EOL since June 2023)
- Declare explicit compatibility with Python 3.11
- Support werkzeug 3.0
- Fail more gracefully if Authlib (OIDC) login provider is down

Version 0.4.9
-------------

- Support authlib 1.1 (remove upper version pin)

Version 0.4.8
-------------

- Fix LDAP TLS configuration

Version 0.4.7
-------------

- Declare explicit compatibility with Python 3.10

Version 0.4.6
-------------

- Support authlib 1.0.0rc1 (up to 1.0.x)

Version 0.4.5
-------------

- Log details when getting oauth token fails

Version 0.4.4
-------------

- Support authlib 1.0.0b2

Version 0.4.3
-------------

- Add ``saml`` provider which supports SAML without the need for Shibboleth and Apache

Version 0.4.2
-------------

- Fix LDAP group membership checks on servers that are not using ``ad_group_style``

Version 0.4.1
-------------

- Support authlib 1.0.0a2

Version 0.4
-----------

- Drop support for Python 2; Python 3.6+ is now required

Version 0.3.5
-------------

- Validate ``next`` URL to avoid having an open redirector

Version 0.3.4
-------------

- Fix authlib dependency to work with 1.0.0a1 (which no longer has a ``client`` extra)

Version 0.3.3
-------------

- Add missing dependencies for ``ldap`` and ``sqlalchemy`` extras
- Add support for authlib 1.0.0a1
- Add explicit support for Python 3.9

Version 0.3.2
-------------

- Require a recent ``python-ldap`` version when enabling the ``ldap`` extra.

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
