# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask_multiauth._compat import add_metaclass


class _GroupMeta(type):
    # TODO: make this more generic and use it in UserProvider, too
    def __new__(mcs, name, bases, dct):
        if bases != (object,):
            supports_user_list = dct.get('supports_user_list')
            if not supports_user_list and 'get_users' in dct:
                raise TypeError('{} cannot override get_users unless supports_user_list is True'.format(name))
            elif supports_user_list and 'get_users' not in dct:
                raise TypeError('{} must override get_users if supports_user_list is True'.format(name))
        return type.__new__(mcs, name, bases, dct)


@add_metaclass(_GroupMeta)
class Group(object):
    """Base class for groups

    :param provider: The user provider instance managing the group.
    :param name: The unique name of the group.
    """

    #: If it is possible to get the list of members of a group.
    supports_user_list = False

    def __init__(self, provider, name):
        self.provider = provider
        self.name = name

    def get_users(self):
        """Returns the members of the group.

        This can also be performed by iterating over the group.
        If the group does not support listing members,
        :exc:`~exceptions.NotImplementedError` is raised.

        :return: An iterable of :class:`.UserInfo` objects.
        """
        if self.supports_user_list:
            raise NotImplementedError
        else:
            raise RuntimeError('This group type does not support retrieving the member list')

    def has_user(self, identifier):
        """Checks if a given user is a member of the group.

        This check can also be performed using the ``in`` operator.

        :param identifier: The `identifier` from a :class:`.UserInfo`
                           provided by the associated user provider.
        """
        raise NotImplementedError

    def __iter__(self):
        return self.get_users()

    def __contains__(self, user_info):
        return self.has_user(user_info)

    def __repr__(self):
        return '<{}({}, {})>'.format(type(self).__name__, self.provider, self.name)
