# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2017 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask_multipass._compat import add_metaclass
from flask_multipass.util import SupportsMeta


@add_metaclass(SupportsMeta)
class Group(object):
    """Base class for groups

    :param provider: The identity provider managing the group.
    :param name: The unique name of the group.
    """

    __support_attrs__ = {'supports_member_list': 'get_members'}
    #: If it is possible to get the list of members of a group.
    supports_member_list = False

    def __init__(self, provider, name):  # pragma: no cover
        self.provider = provider
        self.name = name

    def get_members(self):  # pragma: no cover
        """Returns the members of the group.

        This can also be performed by iterating over the group.
        If the group does not support listing members,
        :exc:`~exceptions.NotImplementedError` is raised.

        :return: An iterable of :class:`.IdentityInfo` objects.
        """
        if self.supports_member_list:
            raise NotImplementedError

    def has_member(self, identifier):  # pragma: no cover
        """Checks if a given identity is a member of the group.

        This check can also be performed using the ``in`` operator.

        :param identifier: The `identifier` from an :class:`.IdentityInfo`
                           provided by the associated identity provider.
        """
        raise NotImplementedError

    def __iter__(self):  # pragma: no cover
        return self.get_members()

    def __contains__(self, identifier):  # pragma: no cover
        return self.has_member(identifier)

    def __repr__(self):
        return '<{}({}, {})>'.format(type(self).__name__, self.provider, self.name)
