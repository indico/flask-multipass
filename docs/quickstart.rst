===========
Quick start
===========

Installation
------------

Installing Flask-Multipass is very easy. Using pip::

    $ pip install Flask-Multipass

.. _initialization:

Initialization
--------------

To start with Multipass, create your Flask application, load your preferred configuration file (more on configuration further in this guide) and create the ``Multipass`` object by passing it the application. Multipass is also using Flask's ``session`` object so make sure you have your secret key set on the Flask app.

.. code-block:: python

    from flask import Flask
    from flask_multipass import Multipass

    app = Flask(__name__)
    app.config.from_pyfile('example.cfg')
    app.secret_key = 'my super secret key'
    multipass = Multipass(app)

If you happen to have more than one application (or you're using an application factory) you can also use ``init_app`` :

.. code-block:: python

    apps = Flask('app1'), Flask('app2')
    multipass = Multipass()
    for app in apps:
        multipass.init_app(app)

Configuration
-------------

The following configuration values exist for Flask-Multipass:

====================================== =========================================
``MULTIPASS_AUTH_PROVIDERS``           Dictionary of authentication providers
``MULTIPASS_IDENTITY_PROVIDERS``       Dictionary of identification providers
``MULTIPASS_PROVIDER_MAP``             Mapping of authentication providers to identification providers
``MULTIPASS_IDENTITY_INFO_KEYS``       Keys used for identification
``MULTIPASS_LOGIN_SELECTOR_TEMPLATE``  Template with selection of login providers
``MULTIPASS_LOGIN_FORM_TEMPLATE``      Template with login form
``MULTIPASS_LOGIN_ENDPOINT``           Endpoint linking to login page
``MULTIPASS_LOGIN_URLS``               List of login URLs
``MULTIPASS_SUCCESS_ENDPOINT``         Endpoint linking to default page after successful login
``MULTIPASS_FAILURE_MESSAGE``          Message to show after unsuccessful login
``MULTIPASS_FAILURE_CATEGORY``         Category of message when flashing after unsuccessful login
``MULTIPASS_ALL_MATCHING_IDENTITIES``  If true, all matching identities are passed after successful authentication
``MULTIPASS_REQUIRE_IDENTITY``         If true, ``IdentityRetrievalFailed`` is raised when no matching identities are found, otherwise empty list is passed
``MULTIPASS_HIDE_NO_SUCH_USER``        If true, ``InvalidCredentials`` instead of ``NoSuchUser`` is raised when no user is found in the system
====================================== =========================================

A configuration example can be found here: :ref:`config_example`

Providers
---------

Providers are objects that take care of the authentication of users (``AuthProvider``) or assigning identity information like name, email, address etc. to users (``IdentityProvider``).

These providers objects can be either **local** (implemented by you) or **external** - from a website allowing use of their authentication on custom applications e.g. GitHub, Facebook etc. Most of the times you will want to use an existing external provider, however this guide also shows how to easily implement your own local providers.

You can of course use **both** local and external providers in the same application with Multipass.

.. _external_providers:

External providers
******************

Configuration
~~~~~~~~~~~~~

Using external providers with Multipass is very easy. First, you need to specify some configuration details for each external provider in the Multipass configuration.


In the following example we use GitHub as external provider. By specifying ``'type': 'authlib'`` we link it to ``AuthlibAuthProvider`` and ``AuthlibIdentityProvider`` classes.  Another type you can use for external provider is ``'type': 'shibboleth'``  for  ``ShibbolethAuthProvider`` and ``ShibbolethIdentityProvider``.

Although using one of the two providers is probably the most common case, you can also write your own class for any desired external provider. You can check out the base classes for :ref:`auth_providers` and :ref:`identity_providers` to get an idea how to implement your own class.

Here is a code example from our configuration file ``example.cfg`` that we load before initializing Multipass:

.. code-block:: python

    MULTIPASS_AUTH_PROVIDERS = {
        'github': {
            'type': 'authlib',
            'title': 'GitHub',
            'authlib_args': {
                'client_id': '',  # put your client id here
                'client_secret': '',  # put your client secret here
                'client_kwargs': {'scope': 'user:email'},
                'authorize_url': 'https://github.com/login/oauth/authorize',
                'access_token_url': 'https://github.com/login/oauth/access_token',
                'userinfo_endpoint': 'https://api.github.com/user',
            }
        }
    }

    MULTIPASS_IDENTITY_PROVIDERS = {
        'github': {
            'type': 'authlib',
            'identifier_field': 'id',
            'mapping': {
                'user_name': 'login',
                'affiliation': 'company'
            }
        }
    }

An important thing to notice here is that we are assigning the ``'identifier_field'`` to the name of the field containing unique user identifier of the external provider. In this GitHub example it's ``'id'``.  This ``'identifier_field'`` is used to connect the identity to the user, so make sure you assign it to the right unique field.

The next thing to notice is the mapping of fields from our application to those of the provider. In this example we map ``'user_name'`` that we use in our application to the ``'login'`` field used in GitHub.

Also make sure to connect the authentication provider to the identity provider in the provider mapping.

.. code-block:: python

    MULTIPASS_PROVIDER_MAP = {
        'github': 'github'
    }

In this example we only have one provider but if you have more than one provider you need to pass a template file to ``MULTIPASS_LOGIN_SELECTOR_TEMPLATE``. In this template users should choose which provider they want to log in with.

.. code-block:: python

    MULTIPASS_LOGIN_SELECTOR_TEMPLATE = 'login_selector.html'


This configuration option can be added to the configuration file you use to initialize your Flask application. (as shown in :ref:`initialization`). However, you can configure Multipass also directly through application object. For example:

.. code-block:: python

    app.config['MULTIPASS_LOGIN_SELECTOR_TEMPLATE'] =  'login_selector.html'

.. _external_login:

External provider login
~~~~~~~~~~~~~~~~~~~~~~~
The easiest way to handle the login operation is to specify the login URLs you're using in the app's configuration. For example:

.. code-block:: python

    MULTIPASS_LOGIN_URLS = {'/my_login/', '/my_login/<provider>'}

(By default,  values ``'/login/'`` and ``'/login/<provider>'`` are set for ``MULTIPASS_LOGIN_URLS`` so if those suit your application there's no need to change them.)

Multipass then binds the ``process_login`` method to these URLs upon initialization of Multipass.

However,  if you wish to execute some additional code before, make ``MULTIPASS_LOGIN_URLS`` empty, handle the login request yourself and then call ``process_login`` on your ``Multipass`` object:

.. code-block:: python

    @app.route('/my_login/', methods=('GET', 'POST'))
    @app.route('/my_login/<provider>', methods=('GET', 'POST'))
    def login(provider=None):
        # Your additional code
        return multipass.process_login(provider)


When calling ``process_login`` with the provider name as an argument the ``initiate_external_login`` on the provider gets called and redirects user to the provider's site to perform login. (In case of local provider ``_login_form`` gets called, see: :ref:`local_login`.) If provider is not specified the ``process_login`` redirects to a login selection template specified in configuration as ``MULTIPASS_LOGIN_SELECTOR_TEMPLATE``.

.. _identity_handler:

Identity handler
~~~~~~~~~~~~~~~~

After a successful authentication response is received from ``initiate_external_login``, the ``handle_auth_success`` method gets called.

``handle_auth_success`` then collects the identities linked to the user and stores the name of the provider that was used to login  as ``'_multipass_login_provider'`` in ``session``. It will be used when logging out.

Then, the method registered via the ``'@multipass.identity_handler'`` decorator is called with one, or a list of ``IdentityInfo`` objects as an argument. (Depending on whether ``MULTIPASS_ALL_MATCHING_IDENTITIES`` is set in the configuration).

Here is an example of a possible ``identity_handler`` method:

.. code-block:: python

    @multipass.identity_handler
    def identity_handler(identity_info):
        identity = Identity.query.filter_by(provider=identity_info.provider.name,
                                            identifier=identity_info.identifier).first()
        if not identity:
            user = User.query.filter_by(email=identity_info.data['email']).first()
        if not user:
            data = identity_info.data
            user = User(id=data['id'], user_name=data['user_name'], email=data['email'], affiliation=data['affiliation'])
            db.session.add(user)
            identity = Identity(provider=identity_info.provider.name, identifier=identity_info.identifier)
            user.identities.append(identity)
        else:
            user = identity.user
            db.session.commit()
            session['user_id'] = user.id

First, we search through the table of identities for a matching ``IdentityInfo.identifier`` (passed as an argument). If a matching identity is not found, we check if there is already such a user in the database, we create a new user if needed and assign a new identity to that user object. Then, we save the user object (new or matched) in the Flask session.




If ``multipass.identity_handler`` decorated method doesn't return anything,
``handle_auth_success`` returns ``redirect_success`` which redirects to URL stored in ``session`` as ``'_multipass_next_url'``.

.. _external_logout:

External provider logout
~~~~~~~~~~~~~~~~~~~~~~~~

``multipass.logout`` should be called by your application upon logout request, passing it the url to redirect to after logout and optionally a flag to clear the session.

.. code-block:: python

    @app.route('/logout')
    def logout():
        return multipass.logout(url_for('index'), clear_session=True)

The ``logout`` method then calls  ``process_logout`` on provider which name was stored in ``session`` as ``'_multipass_login_provider'`` upon login.

In the ``process_logout`` method the provider can implement some provider-specific actions such as sending a logout notification to the provider or redirecting to a SSO logout page. The ``return_url`` from argument can be passed further if the external provider allows to specify the URL to redirect to after logging out.

Notice that in our example we are using ``AuthlibAuthProvider`` which has no ``process_logout`` method implemented. Therefore we are passing ``'true'`` for ``clear_session`` to remove ``'user_id'`` that we saved in ``session`` earlier and log out the user in this way.

If there is no provider specified in ``'_multipass_login_provider'`` the ``logout`` method redirects straight to the  ``return_url``

.. _local_providers:

Local providers
***************

Configuration
~~~~~~~~~~~~~

This section shows an example of a configuration for an application using a local provider. If you wish to use both external and local providers, don't hesitate to specify both local and external providers in the same configuration and just follow our guide also on :ref:`external_providers`

In this example ``'test_auth_provider'`` is a dummy local authentication provider, it's linked to the ``'test_identity_provider'`` as specified in ``MULTIPASS_PROVIDER_MAP``. Specifying ``'type'`` as ``'static'`` links those providers to our ``StaticAuthProvider`` and ``StaticIdentityProvider`` example classes (More on those classes later).

In the ``identities`` setting of ``'test_auth_provider'`` we specify key-value pairs of username (*Pig*) and password (*pig123*), those are used for authentication by Multipass. In this example, the usernames are used as unique identifier for users. In ``identities`` settings of ``'test_identity_provider'`` we assign info keys dictionary to usernames. We also need to specify these keys in ``MULTIPASS_IDENTITY_INFO_KEYS``.

.. code-block:: python

    MULTIPASS_AUTH_PROVIDERS = {
        'test_auth_provider': {
            'type': 'static',
            'title': 'Insecure dummy auth',
            'identities': {
                'Pig': 'pig123',
                'Bunny': 'bunny123'
            }
        }
    }

    MULTIPASS_IDENTITY_PROVIDERS = {
        'test_identity_provider': {
            'type': 'static',
            'identities': {
                'Pig': {'email': 'guinea.pig@example.com', 'name': 'Guinea Pig', 'affiliation': 'Pig University'},
                'Bunny': {'email': 'bugs.bunny@example.com', 'name': 'Bugs Bunny', 'affiliation': 'Bunny Inc.'}
            },
            'groups': {
                'Admins': ['Pig'],
                'Everybody': ['Pig', 'Bunny'],
            }
        }
    }

    MULTIPASS_PROVIDER_MAP = {
        'test_auth_provider': 'test_identity_provider'
    }

    MULTIPASS_IDENTITY_INFO_KEYS = ['email', 'name', 'affiliation']

We also need to specify the template with a login form for our provider:

.. code-block:: python

    MULTIPASS_LOGIN_FORM_TEMPLATE = 'login_form.html'

Implementing providers
~~~~~~~~~~~~~~~~~~~~~~

Let's create our authentication provider class, which should inherit from ``AuthProvider``.
We should also specify the login form class (which inherits from ``FlaskForm``) which we use for the login operation of this provider.

.. code-block:: python

    class StaticLoginForm(FlaskForm):
        username = StringField('Username', [DataRequired()])
        password = PasswordField('Password', [DataRequired()])

    class StaticAuthProvider(AuthProvider):
        login_form = StaticLoginForm

.. _local_login:

Local provider login
~~~~~~~~~~~~~~~~~~~~

The process of handling URLs for login is the same as with external providers, therefore please check the :ref:`external_login` part of this guide.

The only difference is that  ``multipass.process_login`` calls the method ``_login_form`` which renders a template specified in ``MULTIPASS_LOGIN_FORM_TEMPLATE`` with the ``login_form`` specified in the authentication provider class.

Once the form is submitted, the method ``process_local_login`` of the authentication provider class is called. In this method you have to implement your authentication logic.

You should raise ``MultipassException`` in case of failed validation. If the validation was successful, the ``AuthInfo`` object should be created and passed to ``multipass.handle_auth_success``. Below is the ``process_local_login`` method from our example provider ``StaticAuthProvider``:

.. code-block:: python

    def process_local_login(self, data):
        username = data['username']
        password = self.settings['identities'].get(username)
        if password is None:
        raise AuthenticationFailed('No such user')
        if password != data['password']:
            raise AuthenticationFailed('Invalid password.')
        auth_info = AuthInfo(self, username=data['username'])
        return self.multipass.handle_auth_success(auth_info)


Identification
~~~~~~~~~~~~~~

The next step after successful authentication is assigning an identity to the user. That's a job for an identity provider so let's have a look how to implement one.

Your identity provider should inherit from the ``IdentityProvider`` base class. The most important method it has to implement is ``get_identity_from_auth``, which accepts ``AuthInfo`` object as an argument and returns the corresponding identity (object of ``IdentityInfo``) based on an identifier.

In our example we search the ``'identities'`` dictionary that we specified in configuration and look for the identity with a matching identifier (``'username'`` in our case).


.. code-block:: python

    class StaticIdentityProvider(IdentityProvider):

        def get_identity_from_auth(self, auth_info):
        identifier = auth_info.data['username']
        user = self.settings['identities'].get(identifier)
        if user is None:
            return None
        return IdentityInfo(self, identifier, **user)

Other methods that should be implemented to ensure the full Multipass functionality can be found further in this guide. See :ref:`identities` and :ref:`groups`

Now let's get back to the identification process.
Once ``handle_auth_success`` is called, it collects the identities linked to the user using the ``get_identity_from_auth`` method we just mentioned.
Once identities are successfully collected, the method registered via the ``'@multipass.identity_handler'`` decorator is called. A method with this decorator must be implemented in your application. Check the :ref:`identity_handler` part of this documentation for more info.

Failed authentication
~~~~~~~~~~~~~~~~~~~~~

In case the authentication was unsuccessful, and ``MultipassException`` was raised, ``handle_auth_error`` flashes the ``MULTIPASS_FAILURE_MESSAGE`` and if the ``redirect_to_login`` argument is set, it redirects to ``MULTIPASS_LOGIN_ENDPOINT``


Local provider logout
~~~~~~~~~~~~~~~~~~~~~

The process of logging out local providers is the same as with external providers.
Please check the :ref:`external_logout` part of this guide.

.. _identities:

Identities
----------

To retrieve an ``IdentityInfo`` object,  your  ``IdentityProvider`` must implement the ``get_identity`` method. Example from ``StaticIdentityProvider``:

.. code-block:: python

    def get_identity(self, identifier):
        user = self.settings['identities'].get(identifier)
        if user is None:
            return None
        return IdentityInfo(self, identifier, **user)

The same applies for searching identities. There you accept a ``criteria`` dictionary as a filter for your search. Example from ``StaticIdentityProvider``:

.. code-block:: python

    def search_identities(self, criteria, exact=False):
        for identifier, user in self.settings['identities'].items():
            for key, values in criteria.items():
                user_value = user.get(key)
                user_values = set(user_value) if isinstance(user_value, (tuple, list)) else {user_value}
                if not any(user_values):
                    break
                elif exact and not user_values & set(values):
                    break
                elif not exact and not any(sv in uv for sv, uv in itertools.product(values, user_values)):
                    break
            else:
                yield IdentityInfo(self, identifier, **user)

Once implemented on your  ``IdentityProvider``, you can also use method  ``search_identities`` on a ``Multipass`` object which will search among all the providers and yield all the ``identity_info``  matching the criteria specified in the argument.

.. code-block:: python

    criteria['name'] = 'Guinea Pig'
    criteria['email'] = 'guinea.pig@example.com'
    results = list(multipass.search_identities(exact=False, **criteria))

.. _groups:

Groups
------

Providers can divide users into groups. This is usually based on the access rights and competences of users, for example: whether they are admins, content managers, regular users, etc. These groups should be specified in the configuration settings of the identity provider. Example from our ``'test_identity_provider'``:

.. code-block:: python

    MULTIPASS_IDENTITY_PROVIDERS = {
        'test_identity_provider': {
        'type': 'static',
        'identities': {
            'Pig': {'email': 'guinea.pig@example.com', 'name': 'Guinea Pig'},
            'Bunny': {'email': 'bugs.bunny@example.com', 'name': 'Bugs Bunny'}
        },
        'groups': {
            'Admins': ['Pig'],
            'Everybody': ['Pig', 'Bunny'],
        }
        }


The provider's group class must inherit from the base class ``Group``. If the group should support members, methods ``get_members`` (returning iterable of ``IdentityInfo`` of the group members) and ``has_member`` must be implemented. Example from our ``StaticGroup``:

.. code-block:: python

    class StaticGroup(Group):
        """A group from the static identity provider"""

        supports_member_list = True

        def get_members(self):
        members = self.provider.settings['groups'][self.name]
        for username in members:
                yield self.provider._get_identity(username)

        def has_member(self, identifier):
        return identifier in self.provider.settings['groups'][self.name]

In your ``IdentityProvider`` class you must specify the group class as ``group_class`` and the flag ``supports_groups`` must be set.

.. code-block:: python


    class StaticIdentityProvider(IdentityProvider):
        supports_groups = True
        group_class = StaticGroup

``Group`` objects can be accessed through ``get_group`` method which has to be implemented in your ``IdentityProvider``. Example from ``StaticIdentityProvider``:

.. code-block:: python

      def get_group(self, name):
          if name not in self.settings['groups']:
              return None
          return self.group_class(self, name)

However, you can also instantiate the ``Group`` object by passing it the ``IdentityProvider`` and specifying the name

.. code-block:: python

    provider = StaticIdentityProvider(multipass, 'test', settings)
    group = StaticGroup(provider, 'Admins')


To search groups you can use ``search_groups`` of ``Multipass`` object by passing the name of the group. But you still need to implement your own ``search_groups`` method in ``IdentityProvider``

.. code-block:: python

    groups = list(multipass.search_groups('Admins'))


Example of ``search_groups`` in our ``StaticIdentityProvider``:

.. code-block:: python

    def search_groups(self, name, exact=False):
        compare = operator.eq if exact else operator.contains
        for group_name in self.settings['groups']:
            if compare(group_name, name):
                yield self.group_class(self, group_name)

Another useful method is ``is_identity_in_group`` which allows you to check whether the user belongs to a certain group.

.. code-block:: python

    if multipass.is_identity_in_group('test_identity_provider', 'Pig', 'Admins'):
