# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask_multiauth._compat import add_metaclass
from flask_multiauth.util import SupportsMeta


@add_metaclass(SupportsMeta)
class Group(object):
    """Base class for groups

    :param provider: The user provider instance managing the group.
    :param name: The unique name of the group.
    """

    __support_attrs__ = {'supports_user_list': 'get_users'}
    #: If it is possible to get the list of members of a group.
    supports_user_list = False

    def __init__(self, provider, name):  # pragma: no cover
        self.provider = provider
        self.name = name

    def get_users(self):  # pragma: no cover
        """Returns the members of the group.

        This can also be performed by iterating over the group.
        If the group does not support listing members,
        :exc:`~exceptions.NotImplementedError` is raised.

        :return: An iterable of :class:`.UserInfo` objects.
        """
        if self.supports_user_list:
            raise NotImplementedError

    def has_user(self, identifier):  # pragma: no cover
        """Checks if a given user is a member of the group.

        This check can also be performed using the ``in`` operator.

        :param identifier: The `identifier` from a :class:`.UserInfo`
                           provided by the associated user provider.
        """
        raise NotImplementedError

    def __iter__(self):  # pragma: no cover
        return self.get_users()

    def __contains__(self, user_info):  # pragma: no cover
        return self.has_user(user_info)

    def __repr__(self):
        return '<{}({}, {})>'.format(type(self).__name__, self.provider, self.name)
