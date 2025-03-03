# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from flask_wtf import FlaskForm
from sqlalchemy import inspect
from wtforms.fields import PasswordField, StringField
from wtforms.validators import DataRequired

from flask_multipass import AuthInfo, AuthProvider, IdentityInfo, IdentityProvider, InvalidCredentials, NoSuchUser


class LoginForm(FlaskForm):
    identifier = StringField('Username', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])


class SQLAlchemyAuthProviderBase(AuthProvider):
    """Provides authentication against passwords stored in SQLAlchemy.

    This provider expects your application to have an "identity" model
    which maps identifiers from IdentityInfo objects to users. For further
    details on how to use this provider, please see the example
    application.

    To use it, you have to subclass it in your application.
    """

    #: The :class:`~flask_wtf.Form` that is used for the login dialog
    login_form = LoginForm
    #: The Flask-SQLAlchemy model representing a user identity
    identity_model = None
    #: The column of the identity model that contains the provider
    #: name. This needs to be a SQLAlchemy column object, e.g.
    #: ``Identity.provider``
    provider_column = None
    #: The column of the identity model that contains the identifier,
    #: i.e. the username. This needs to be a SQLAlchemy column object,
    #: e.g. ``Identity.identifier``
    identifier_column = None

    def check_password(self, identity, password):
        """Checks the entered password.

        :param identity: An instance of :attr:`identity_model`.
        :param password: The password entered by the user.
        """
        raise NotImplementedError

    def process_local_login(self, data):
        identity = self.identity_model.query.filter(type(self).provider_column == self.name,
                                                    type(self).identifier_column == data['identifier']).first()
        if not identity:
            raise NoSuchUser(provider=self, identifier=data['identifier'])
        if not self.check_password(identity, data['password']):
            raise InvalidCredentials(provider=self, identifier=data['identifier'])
        auth_info = AuthInfo(self, identity=identity)
        return self.multipass.handle_auth_success(auth_info)


class SQLAlchemyIdentityProviderBase(IdentityProvider):
    """Provides identity information for users stored in SQLAlchemy.

    This provider expects your application to have an "identity" model
    which maps identifiers from IdentityInfo objects to users. For further
    details on how to use this provider, please see the example
    application.

    The provider returns all columns from the user model; use the
    configurable mapping to restrict the data returned.

    To use it, you have to subclass it in your application.
    """

    #: The relationship of the identity model that points to the
    #: associated user object.  This can be either a SQLAlchemy
    #: relationship object such as ``Identity.user`` or a string
    #: containing the attribute name of the relationship.
    identity_user_relationship = None
    #: The Flask-SQLAlchemy model representing a user.
    user_model = None
    #: Getting an identity based on the identifier does not make lots
    #: of sense for identities coming from the local database.
    supports_get = False

    def get_identity_from_auth(self, auth_info):
        cls = type(self)
        identity = auth_info.data['identity']
        if isinstance(cls.identity_user_relationship, str):
            relationship_name = cls.identity_user_relationship
        else:
            relationship_name = cls.identity_user_relationship.key
        user = getattr(identity, relationship_name)
        # Get all columns from the user model
        mapper = inspect(self.user_model)
        data = {x.key: getattr(user, x.key) for x in mapper.attrs}
        return IdentityInfo(self, identity.identifier, **data)
