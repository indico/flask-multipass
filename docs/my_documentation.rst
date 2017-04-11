Flask-Multipass
===============

Installation
------------

Installing Flask-Multipass is very easy. Using pip::

    $ pip install Flask-Multipass

Initialization
--------------

To start with Multipass, create your Flask application, load the preferred configuration (more on configuration further in this guide) and create the ``Multipass`` object by passing it the application. Multipass is also using ``session`` so make sure you have your secret key set on the flask app.

.. code-block:: python

    from flask import Flask
    from flask_multipass import Multipass

    app = Flask(__name__)
    app.config.from_pyfile('example.cfg')
    app.secret_key = 'my super secret key'
    multipass = Multipass(app)

If you happen to have more than one application (or you're using an application factory) you can also use ``init_app`` :

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
``MULTIPASS_FAILURE_MESSAGE``          Message to show after unsuccessful login
``MULTIPASS_FAILURE_CATEGORY``         Category of message when flashing after unsuccessful login
``MULTIPASS_ALL_MATCHING_IDENTITIES``  If true, all matching identities are passed after successful authentication
``MULTIPASS_REQUIRE_IDENTITY``         If true, ``IdentityRetrievalFailed`` is raised when no matching identities are found, otherwise empty list is passed
====================================== =========================================

A configuration example can be found here

< link to config.example.rst>

Providers
------------

Providers are objects that take care of authentication of users (``AuthProvider``) or assigning identity information like name, email, address etc. to users (``IdentityProvider``).

These providers objects can be either **local** (implemented by you) or **external** - from website allowing use of their authentication on custom applications e.g. GitHub, Facebook etc. In most cases people only want to use these external providers, however this guide also shows how to easily implement your own local providers. 

You can of course use **both** local and external providers in the same application with Mutlipass. 



External providers 
---------------------

Configuration
---------------------

Using external providers with Multipass is very easy. First, you need to specify configuration details for each external provider in the Multipass configuration.


In our example we use GitHub as external provider. By specifying ``'type': 'oauth'`` we link it to ``OAuthAuthProvider`` and ``OAuthIdentityProvider`` classes.  Another type you can use for external provider is ``'type': 'shibboleth'``  for  ``ShibbolethAuthProvider`` and ``ShibbolethIdentityProvider``.

 Although using one of the two providers is probably the most common case, you can also write your own class for desired external provider. You can check out the base classes  < link  ``AuthProvider``>  ,  < link  ``IdentityProvider``> or already implemented  < link  ``ShibbolethAuthProvider``>  to get an idea how to implement your own class.

Code from our  configuration file 'example.cfg' that we load before initializing multipass:

.. code-block:: python

	_github_oauth_config = {
	    'consumer_key': '',  # put your key here
	    'consumer_secret': '',  # put your secret here
	    'request_token_params': {'scope': 'user:email'},
	    'base_url': 'https://api.github.com',
	    'request_token_url': None,
	    'access_token_method': 'POST',
	    'access_token_url': 'https://github.com/login/oauth/access_token',
	    'authorize_url': 'https://github.com/login/oauth/authorize'
	}

	MULTIPASS_AUTH_PROVIDERS = {
	    'github': {
		'type': 'oauth',
		'title': 'GitHub',
		'oauth': _github_oauth_config
	    }
	}

	MULTIPASS_IDENTITY_PROVIDERS = {
	    'github': {
		'type': 'oauth',
		'oauth': _github_oauth_config,
		'endpoint': '/user',
		'identifier_field': 'id',
		'mapping': {
		    'user_name': 'login',
		    'affiliation': 'company'
		}
	    }
	}
	
Important thing to notice here is assigning the ``'identifier_field'`` to name of the field containing unique user identifier of the external provider. In this GitHub example its ``'id'``.  This ``'identifier_field'`` is used to connect the identity to the user, so make sure you assign it to the right unique field.

Next thing to notice is mapping of fields from our application to those of the provider. In this example we map ``'user_name'`` - that we use in our application to ``'login'`` field used in GitHub.

Also make sure to connect the authentication provider to identity provider in provider mapping.

.. code-block:: python

	MULTIPASS_PROVIDER_MAP = {
	    'github': 'github'
	}
	
In this example we only have one provider but if you have more than one provider you need to pass a template file to ``MULTIPASS_LOGIN_SELECTOR_TEMPLATE``. In this template users should choose which provider they want to log in with.

.. code-block:: python

	MULTIPASS_LOGIN_SELECTOR_TEMPLATE = 'login_selector.html'
	
	
This configuration can be added to your flask configuration file that you use when initializing flask application. (as shown in < Initialization>) However, you can configure multipass also directly through application object. for example:

.. code-block:: python

	app.config['MULTIPASS_LOGIN_SELECTOR_TEMPLATE'] =  'login_selector.html'

Login
---------------------
The easiest way to process login is to specify your prefered login URLs in configuration as value for 	``MULTIPASS_LOGIN_URLS``. For example:   

.. code-block:: python

	MULTIPASS_LOGIN_URLS = {'/my_login/', '/my_login/<provider>'}
	
(By default,  values ``'/login/'`` and ``'/login/<provider>'`` are set for ``MULTIPASS_LOGIN_URLS`` so if those suits your application there's no need to change them.)
	
Multipass then binds  ``process_login`` method to these URLs upon initialization of multipass.

However,  if you wish to execute some additional code before, make ``MULTIPASS_LOGIN_URLS`` empty,  handle login request yourself and then call ``process_login``on your  ``Multipass`` object:

.. code-block:: python

	@app.route('/my_login/', methods=('GET', 'POST'))
	@app.route('/my_login/<provider>', methods=('GET', 'POST'))
	def login(provider=None):
	    # Your additional code
	    return multipass.process_login(provider)
	

When calling ``process_login`` with provider name as an argument the ``initiate_external_login`` on the provider gets called and redirects user to the provider's site to perform login.( In case of local provider <``_login_form`` link to login of local providers> gets called.) If provider is not specified the ``process_login`` redirects to a login selection template specified in configuration as ``MULTIPASS_LOGIN_SELECTOR_TEMPLATE``. 

Identification
-------------------------

After successful authentication response received from ``initiate_external_login``, method ``handle_auth_success`` gets called.

``handle_auth_success`` then collects the identities linked to the user and stores the name of the provider that was used to login  as ``'_multipass_login_provider'`` in ``session``, it will be used when logging out.

Then, the method registered via ``'@multipass.identity_handler'`` decorator is called with one, or list of ``IdentityInfo`` objects as an argument. (Depending whether ``MULTIPASS_ALL_MATCHING_IDENTITIES`` is set in configuration).

Following is our example of ``identity_handler`` method. First, we search through table of identities for one matching ``IdentityInfo.identifier`` from argument. If the identity is not found, we check if we already have this user in the database, we create a new user if needed and assign a new identity to the user object. Then we save this user (or the one found) to the session.
 
 
 ???? Should I show user and identity classes from example so its more clear how the code works?

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


If ``multipass.identity_handler`` decorated method doesn't return anything, 
``handle_auth_success`` returns ``redirect_success`` which redirects to URL stored in ``session`` as ``'_multipass_next_url'``.



Logout
---------

``multipass.logout`` should be called by your application upon logout request, passing it the url to redirect to after logout and optionally a flag to clear session.

.. code-block:: python

	@app.route('/logout')
	def logout():
	    return multipass.logout(url_for('index'), clear_session=True)

The ``logout`` method then calls  ``process_logout`` on provider which name was stored in ``session`` as ``'_multipass_login_provider'`` upon login.

In ``process_logout`` method the provider can implement some provider-specific actions such as sending a logout notification to the provider or redirecting to a SSO logout page. The ``return_url`` from argument can be passed further if the external provider allows to specify the URL to redirect to after logging out.

Notice that in our example we are using ``OAuthAuthProvider`` which has no 	``process_logout`` method implemented. Therefore we are passing ``'true'`` for ``clear_session`` to remove ``'user_id'`` that we saved in ``session`` earlier and log out the user in this way. 

If there is no provider specified in ``'_multipass_login_provider'`` the ``logout`` method redirects straight to the  ``return_url`` 


Local providers
---------------------

Configuration
---------------------

In this section we show example of configuration for application using a local provider. If you wish to use both external and local providers, don't hasitate to specify both local and external providers in the same configuration and just follow our guide also on < external providers>

In this example ``'test_auth_provider'`` is a dummy local authentication provider, it's linked to the ``'test_identity_provider'`` as specified in ``MULTIPASS_PROVIDER_MAP``. Specifying ``'type'`` as ``'static'`` links those providers to our ``StaticAuthProvider`` and ``StaticIdentityProvider`` example classes. (More on those classes later)

In ``identities`` settings of ``'test_auth_provider'`` we specify key-value pairs of username (Pig) and password (pig123), those are used for authentication by Multipass. In ``identities`` settings of ``'test_identity_provider'`` we assign info keys dictionary to usernames. We also need to specify these keys in ``MULTIPASS_IDENTITY_INFO_KEYS``.

 In this example, the usernames are used as unique identifier for users.

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
---------------------

Let's create our authentication provider class, which should inherit from ``AuthProvider``.
We should also specify the login form class (which inherits from ``FlaskForm``) which we use for login of this provider.

.. code-block:: python

	class StaticLoginForm(FlaskForm):
	    username = StringField('Username', [DataRequired()])
	    password = PasswordField('Password', [DataRequired()])

	class StaticAuthProvider(AuthProvider):
	    login_form = StaticLoginForm
    
Login
---------------------

Process of handling URLs for login is the same as with external providers therefore please check the <.. External providers login> part of this guide. 

The only difference is that  ``multipass.process_login`` calls method ``_login_form`` which renders a template specified in ``MULTIPASS_LOGIN_FORM_TEMPLATE`` with the ``login_form`` specified in the authentication provider class.

Once the form is submitted method ``process_local_login`` of authentication provider class is called. In this method you have to implement your authentication logic. 

You should raise ``MultipassException`` in case of failed validation. If the validation was successful, ``AuthInfo`` object should be created and passed to ``multipass.handle_auth_success``. Bellow is ``process_local_login`` method from our example provider ``StaticAuthProvider``:
 
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
-------------------------

The next step after successful authentication is assigning an identity to the user. That's a job of identity provider so let's have a look how to implement one.

Your identity provider should inherit from ``IdentityProvider`` base class. The most important method it has to implement is ``get_identity_from_auth``. Which accepts ``AuthInfo`` object as an argument and returns the corresponding identity (object of ``IdentityInfo``) based on identifier. 

In our example we search the ``'identities'`` dictionary that we specified in configuration and look for the identity with matching identifier ( 'username' in our case).


.. code-block:: python

	class StaticIdentityProvider(IdentityProvider):

		def get_identity_from_auth(self, auth_info):
			identifier = auth_info.data['username']	
			user = self.settings['identities'].get(identifier)
			if user is None:
			    return None
			return IdentityInfo(self, identifier, **user)
			
Other methods that should be implemented to ensure the full Multipass functionality can be found further in this guide. 

See <.. Identities> <... Groups>

Now let's get back to the identification process. 
Once ``handle_auth_success`` is called, it collects the identities linked to the user using the ``get_identity_from_auth`` we just mentioned. 
Once identities are successfully collected, the method registered via ``'@multipass.identity_handler'`` decorator is called. A method with this decorator must be implemented in your application. Check the <.. successful athentication> part of this documentation for more info.

Failed authentication
---------------------------

In case the authentication was unsuccessful, and ``MultipassException`` was raised, ``handle_auth_error`` flashes the ``MULTIPASS_FAILURE_MESSAGE`` and if ``redirect_to_login`` argument is set, it redirects to ``MULTIPASS_LOGIN_ENDPOINT``


Logout
---------

Process of logging out local providers is the same as with external providers.
Please check the <.. external providers logout> part of this guide. 

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

Providers can divide users into groups. This is usually based on access rights and competences of users. For example group of admins, content managers, regular users etc. These groups should be specified in the configuration settings of identity provider. Example from our 'test_identity_provider': 

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
			return identifier in self.provider.settings['groups'][self.name]affiliation
		
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


Things that I think are not necessary anymore (and were in the guide before)
-------
	
	
Then, we'll call ``register_provider``, which will associate a provider class with a provider type specified in the configuration.


.. code-block:: python

	multipass.register_provider(FooProvider, 'static')
	
To instantiate new providers you need to call ``_create_providers`` with key and base class arguments referring to type of providers you registered:

.. code-block:: python
    	
 	multipass._create_providers('AUTH', AuthProvider)

or:

.. code-block:: python

	multipass._create_providers('IDENTITY', IdentityProvider)
	
	
	Local  login
----------------	 

In case of local provider the form can be retrieved using:

.. code-block:: python

	form = provider.login_form()

After the form is submitted it can easily be handled:

.. code-block:: python

	if form.validate_on_submit():
  		response = multipass.handle_login_form(provider, form.data)
  		
  		
  		
Accessing providers : 
	
Providers can be access through the ``auth_providers`` property:

.. code-block:: python

	provider = multipass.auth_providers['test_provider']

or in case of only one provider:

.. code-block:: python

	provider = multipass.single_auth_provider
        
