
.. _config_example:

Configuration example
=====================

This configuration can be added to your Flask configuration file that you use when initializing flask application. However, you can configure Multipass also directly through application object for example:

.. code-block:: python

	app.config['MULTIPASS_LOGIN_URLS'] = {'/my_login/', '/my_login/<provider>'}

Here you can see an example configuration for an application using both external and local providers.

``'test_auth_provider'`` is a dummy example of a local authentication provider, it's linked to the ``'test_identity_provider'`` as specified in ``MULTIPASS_PROVIDER_MAP``. You can read more about the configuration of local providers here: :ref:`local_providers`

``'github'``, ``'my_shibboleth'`` and ``'my-ldap'`` are examples of external providers. More on configuration of external providers:  :ref:`external_providers`

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

	_my_ldap_config = {
	    'uri': 'ldaps://ldap.example.com:636',
	    'bind_dn': 'uid=admin,DC=example,DC=com',
	    'bind_password': 'p455w0rd',
	    'timeout': 30,
	    'verify_cert': True,
	    # optional: if not present, uses certifi's CA bundle (if installed)
	    'cert_file': 'path/to/server/cert',
	    'starttls': False,
	    'page_size': 1000,

	    'uid': 'uid',
	    'user_base': 'OU=Users,DC=example,DC=com',
	    'user_filter': '(objectCategory=person)',

	    'gid': 'cn',
	    'group_base': 'OU=Organizational Units,DC=example,DC=com',
	    'group_filter': '(objectCategory=groupOfNames)',
	    'member_of_attr': 'memberOf',
	    'ad_group_style': False,
	}

	MULTIPASS_AUTH_PROVIDERS = {
	    'test_auth_provider': {
		'type': 'static',
		'title': 'Insecure dummy auth',
		'identities': {
		    'Pig': 'pig123',
		    'Bunny': 'bunny123'
		}
	    },
	    'github': {
		'type': 'oauth',
		'title': 'GitHub',
		'oauth': _github_oauth_config
	    },
	    'my-ldap': {
		'type': 'ldap',
		'title': 'My Organization LDAP',
		'ldap': _my_ldap_config,
	    },
	    'sso': {
		'type': 'shibboleth',
		'title': 'SSO',
		'callback_uri': '/shibboleth/sso',
		'logout_uri': 'https://sso.example.com/logout',
		# optional: defaults to 'ADFS_'
		'attrs_prefix': 'ADFS_',
		# optional: if True, gets the fields from the request headers instead,
		# defaults to False
		'use_headers': False
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
	    },
	    'github': {
		'type': 'oauth',
		'oauth': _github_oauth_config,
		'endpoint': '/user',
		'identifier_field': 'id',
		'mapping': {
		    'user_name': 'login',
		    'affiliation': 'company'
		}
	    },
	    'my-ldap': {
		'type': 'ldap',
		'ldap': _my_ldap_config,
		'mapping': {
		    'name': 'givenName',
		    'email': 'mail',
		    'affiliation': 'company'
		}
	    },
	    'my_shibboleth': {
		'type': 'shibboleth',
		'mapping': {
		    'email': 'ADFS_EMAIL',
		    'name': 'ADFS_FIRSTNAME',
		    'affiliation': 'ADFS_HOMEINSTITUTE'
		}
	    }
	}

	MULTIPASS_PROVIDER_MAP = {
	    'test_auth_provider': 'test_identity_provider',
	    'my-ldap': 'my-ldap',
	    'my_shibboleth': 'my_shibboleth',
		# You can also be explicit (only needed for more complex links)
	    'github': [
		{
		    'identity_provider': 'github'
		}
	    ]
	}

	MULTIPASS_LOGIN_FORM_TEMPLATE = 'login_form.html'
	MULTIPASS_LOGIN_SELECTOR_TEMPLATE = 'login_selector.html'
	MULTIPASS_LOGIN_URLS = {'/my_login/', '/my_login/<provider>'}
	MULTIPASS_IDENTITY_INFO_KEYS = ['email', 'name', 'affiliation']
