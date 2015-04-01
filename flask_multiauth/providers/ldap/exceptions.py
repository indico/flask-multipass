from flask_multiauth.exceptions import MultiAuthException


class LDAPException(MultiAuthException):
    """Base class for MultiAuth LDAP exceptions"""


class LDAPServerError(LDAPException):
    """Indicates the LDAP server had an unexpected behavior"""
