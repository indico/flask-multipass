Changelog
=========

Version 0.11
------------

- Drop support for Python 3.9 (3.9 is EOL since Oct 2025)
- Add support for Python 3.14
- shibboleth: Fix encoding of UTF-8 values incorrectly decoded as Latin-1
- Fix open redirect caused by browsers accepting certain invalid URLs such
  as ``////example.com`` and treating them like ``//example.com``

Version 0.10
------------

- Allow overriding the message of ``NoSuchUser`` and ``InvalidCredentials``, and
  make its other arguments keyword-only

Version 0.9
-----------

- Include the username in the ``identifier`` attribute of the ``NoSuchUser``
  exception so applications can apply e.g. per-username rate limiting
- Fail silently when there's no ``objectSid`` for an AD-style LDAP group

Version 0.8
-----------

- Reject ``next`` URLs containing linebreaks gracefully
- Look for ``logout_uri`` in top-level authlib provider config instead of the
  ``authlib_args`` dict (the latter is still checked as a fallback)
- Include ``id_token_hint`` in authlib logout URL
- Add ``logout_args`` setting to authlib provider which allows removing some of
  the query string arguments that are included by default

Version 0.7
-----------

- Support multiple id fields in SAML identity provider
- Include ``client_id`` in authlib logout URL since some OIDC providers may require this
- Allow setting timeout for authlib token requests (default: 10 seconds)
- Add new ``MULTIPASS_HIDE_NO_SUCH_USER`` config setting to convert ``NoSuchUser``
  exceptions to ``InvalidCredentials`` to avoid disclosing whether a username is valid
- Include the username in the ``identifier`` attribute of the ``InvalidCredentials``
  exception so applications can apply e.g. per-username rate limiting

Version 0.6
-----------

- Drop support for Python 3.8 (3.8 is EOL since Oct 2024)
- Remove upper version pins of dependencies
- Support friendly names for SAML assertions (set ``'saml_friendly_names': True``
  in the auth provider settings)
- Include more verbose authentication data in ``IdentityRetrievalFailed`` exception details

Version 0.5.6
-------------

- Reject invalid ``next`` URLs with backslashes that could be used to trick browsers into
  redirecting to an otherwise disallowed host when doing client-side redirects

Version 0.5.5
-------------

- Ensure only valid schemas (http and https) can be used when validating the ``next`` URL
- Deprecate the ``flask_multipass.__version__`` attribute

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
