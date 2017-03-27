Flask-Multipass
===============

Installation
------------

Installing Flask-Multipass is very easy using pip::

    $ pip install Flask-Multipass

Initialization
--------------

To start with Multipass, create your Flask application, load the prefered configuration and create the ``Multipass`` object by passing it the application:

.. code-block:: python

    from flask import Flask
    from flask_multipass import Multipass

    app = Flask(__name__)
    app.config.from_pyfile('example.cfg')
    multipass = Multipass(app)

When you have more then one application or you are using an application factory you can also use ``init_app`` :

.. code-block:: python

    apps = Flask('test'), Flask('test')
    multipass = Multipass()
    for app in apps:
        multipass.init_app(app)

Configuration
--------------

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
``MULTIPASS_FAILURE_MESSAGE``          Message to show after unsuccessfull login
``MULTIPASS_FAILURE_CATEGORY``         Category of message when flashing after unsuccessful login
``MULTIPASS_ALL_MATCHING_IDENTITIES``  If true, all matching identities are passed after successful authentication
``MULTIPASS_REQUIRE_IDENTITY``         If true, ``IdentityRetrievalFailed`` is raised when no matching identities are found, othwerwise empty list is passed
====================================== =========================================

Configuration example can be found here

< link to config.example.rst>

Registering providers
---------------------

You can register new provider using the following commands. Remember that your provider class must be a subclass of either ``AuthProvider`` or ``IdentityProvider``:

.. code-block:: python

	class FooProvider(AuthProvider):
		pass

Then you pass this class to ``register_provider`` with second argument beeing the type name of the provider specified in configuration. Remember that type names must be unique. :

.. code-block:: python

	app = Flask('test')
	app.config['MULTIPASS_AUTH_PROVIDERS'] = {
		'test_auth_provider': {'type': 'test'}
	}
	multipass = Multipass(app)
	multipass.register_provider(FooProvider, 'test')
	
To instantiate new providers you need to call ``_create_providers`` with key and base class arguments referring to type of providers you registered:

.. code-block:: python
    	
 	multipass._create_providers('AUTH', AuthProvider)

or:

.. code-block:: python

	multipass._create_providers('IDENTITY', IdentityProvider))
	
Accessing providers
---------------------
	
Providers can be access through ``auth_providers`` property:

.. code-block:: python

	provider = multipass.auth_providers['test_provider']

or in case of only one provider:

.. code-block:: python

	provider = multipass.single_auth_provider

Processing login
----------------
By default, the ``process_login`` method is assigned to the URLs specified in ``MULTIPASS_LOGIN_URLS`` upon initialization of Multipass:

.. code-block:: python

	def _create_login_rule(self):
		"""Creates the login URL rule if necessary"""
		endpoint = current_app.config['MULTIPASS_LOGIN_ENDPOINT']
		rules = current_app.config['MULTIPASS_LOGIN_URLS']
		if rules is None:
		    return
		for rule in rules:
		    current_app.add_url_rule(rule, endpoint, self.process_login, methods=('GET', 'POST'))

``process_login`` then returns the login form of the provider or initializes the external login in case of external provider.
If no provider is specified the method renders the login selection template specified in ``MULTIPASS_LOGIN_SELECTOR_TEMPLATE``

However, you can also initialize login using the following:

To initiliaze external login for provider without a login form:

.. code-block:: python

	provider.initiate_external_login()
	
External  login
----------------	

External providers override the ``initiate_external_login`` method, handling the login procedure themselves and returning ``flask.Response`` usually created by ``flask.Redirect``

Local  login
----------------	 

In case of local provider the form can be retrieved using:

.. code-block:: python

	form = provider.login_form()

After the form is submiitted it can easily be handled:

.. code-block:: python

	if form.validate_on_submit():
  		response = multipass.handle_login_form(provider, form.data)

Credentials validation
----------------------
``handle_login_form`` then calls ``process_local_login`` on the provider. Local providers must override this method, raising ``MultipassException`` in case of failed validation. If the validation was successful, ``AuthInfo`` object is created and passed to ``handle_auth_success``. Bellow is ``process_local_login`` method from our example provider ``StaticAuthProvider``:

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

Successful authentication
-------------------------

``handle_auth_success`` then collects the identities linked to the user using method ``get_identity_from_auth`` which has to be overriden in ``IdentityProvider`` class and return ``IdentityInfo``  object. The ``identifier`` is a unique string used to identify the identity, in this example it's user's username. Example from ``StaticIdentityProvider``

.. code-block:: python

	def get_identity_from_auth(self, auth_info):
		identifier = auth_info.data['username']	
		user = self.settings['identities'].get(identifier)
		if user is None:
		    return None
		return IdentityInfo(self, identifier, **user)

Once identities are successfuly collected, the name of the AuthProvider (``auth_info.provider.name``) is stored in ``session`` as ``'_multipass_login_provider'`` and will be used for logout. Then, the method registered via ``'@multipass.identity_handler'`` decorator is called with one, or list of ``IdentityInfo`` objects as an argument. (Depending whether ``MULTIPASS_ALL_MATCHING_IDENTITIES`` is set in configuration) Following is a good example of the method. First, we search through table of identities for one matching ``IdentityInfo.identifier`` from argument. If such identity is found, login can be performed, otherwise we register a new user or if the user is already in the system we create a new identity, link it to the existing user and proceed to login.

.. code-block:: python

	@multipass.identity_handler
	def process_identity(identity_info):
	    identity = Identity.query.filter_by(provider=identity_info.provider.name,
		                                identifier=identity_info.identifier).first()
	    if identity is None:
			user = User.query.filter_by(email=identity_info.data['email']).first()
			if not user:
		    	# Redirect to register page
		    	return redirect(url_for('auth.register', provider=identity_info.provider.name))
			else:
			    # Create new identity and link with already existing account
			    identity = Identity(user=user, provider=identity_info.provider.name,
						identifier=identity_info.identifier, data=identity_info['data'],
						multipass_data=identity_info['multipass_data'])
			    user.identities.append(identity)
	    else:
			user = identity.user
	    login_user(user, identity)

If ``multipass.identity_handler`` decorated method doesn't return anything, 
``handle_auth_success`` returns ``redirect_success`` which redirects to URL stored in ``session`` as ``'_multipass_next_url'``. This URL can be set using the ``set_next_url`` method :

.. code-block:: python

    def set_next_url(self):
        """Saves the URL to redirect to after logging in."""
        next_url = request.args.get('next')
        if next_url:
            session['_multipass_next_url'] = next_url

If the ``'_multipass_next_url'`` is not set, ``redirect_success`` redirects to ``MULTIPASS_SUCCESS_ENDPOINT`` from Multipass configuration.


Failed authentication
---------------------------

In case the autherntication was unsuccessful, and ``MultipassException`` was raised, ``handle_auth_error`` flashes the ``MULTIPASS_FAILURE_MESSAGE`` and if ``recdirect_to_login`` argument is set, it redirects to ``MULTIPASS_LOGIN_ENDPOINT``


Logout
---------

``multipass.logout`` should be called by your application upon logout request, passing it the url to redirect to after logout and optionaly a flag to clear session.

.. code-block:: python

	return multipass.logout(request.args.get('next'), clear_session=True)

The ``logout`` method then calls  ``process_logout`` on provider which name was stored in ``session`` as ``'_multipass_login_provider'`` upon login. In ``process_logout``method the provider can implement some provider-specific actions such as sending a logout notification to the provider or redirecting to a SSO logout page. The ``return_url`` from argument can be passed further if the external provider allows to specify the URL to redirect to after logging out.

If there is no provider specified in ``'_multipass_login_provider'`` the ``logout`` method redirects straight to the  ``return_url`` 

Identities
----------

To retrieve ``IdentityInfo`` object  your  ``IdentityProvider`` must implement ``get_identity`` method. Example from ``StaticIdentityProvider``:

.. code-block:: python

    def get_identity(self, identifier):
        user = self.settings['identities'].get(identifier)
        if user is None:
            return None
        return IdentityInfo(self, identifier, **user)

Same applies for searching identities. There you accept ``criteria`` dictionary as a filter for your search. Example from ``StaticIdentityProvider``:

.. code-block:: python

    def search_identities(self, criteria, exact=False):
        for identifier, user in iteritems(self.settings['identities']):
            for key, values in iteritems(criteria):
                # same logic as multidict
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

Once implemented on your  ``IdentityProvider`` you can also use method  ``search_identities`` on ``Multipass`` object which will search among all the providers and yield all the ``identity_info``  matching the crIteria specified in the argument. 

.. code-block:: python

	criteria['name'] = 'Guinea Pig'
	criteria['email'] = 'guinea.pig@example.com'
	results = list(multipass.search_identities(exact=False, **criteria))

Groups
-------

Providers can divide users into groups. This is usually based on acces rights and competencies of users. For example group of admins, content managers, regular users etc. These groups should be specified in the configuration settings of identity provider. Example from config.example: 

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

Provider's group class must inherit from base class ``Group``. If the group should support members, methods ``get_members`` (returning iterable of ``IdentityInfo`` of the group members) and ``has_member`` must be implemented. Example from our ``StaticGroup``:

.. code-block:: python

	class StaticGroup(Group):
	    """A group from the static identity provider"""

	    supports_member_list = True

	    def get_members(self):
			members = self.provider.settings['groups'][self.name]
			for username in members:
		    	yield self.provider._get_identity(username)

	    def has_member(self, identifier):
			return identifier in self.provider.settings['groups'][self.name]s
		
In ``IdentityProvider`` this class must be specified in  ``group_class`` and flag ``supports_groups`` must be set.

.. code-block:: python


	class StaticIdentityProvider(IdentityProvider):
	    supports_groups = True
	    group_class = StaticGroup
	    
``Group`` objects can be accessed through ``get_group`` method which has to be implemented in your ``IdentityProvider``. Example from ``StaticIdentityProvider``

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
        