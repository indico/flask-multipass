# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

from flask import Flask, render_template
from flask_multiauth import MultiAuth
from flask_multiauth.providers.oauth import OAuthAuthProvider


app = Flask(__name__)
app.debug = True
app.secret_key = 'fma-example'
multiauth = MultiAuth(app)

github_config = {
    'type': OAuthAuthProvider,
    'title': 'GitHub',
    'oauth': {
        'consumer_key': '',  # your client id
        'consumer_secret': '',  # your client secret
        'request_token_params': {'scope': 'user:email'},
        'base_url': 'https://api.github.com/',
        'request_token_url': None,
        'access_token_method': 'POST',
        'access_token_url': 'https://github.com/login/oauth/access_token',
        'authorize_url': 'https://github.com/login/oauth/authorize'
    },
    'token_field': 'access_token'
}

app.config['WTF_CSRF_ENABLED'] = False
app.config['MULTIAUTH_LOGIN_FORM_TEMPLATE'] = 'login_form.html'
app.config['MULTIAUTH_AUTH_PROVIDERS'] = {
    'test': {
        'type': 'static',
        'title': 'Insecure dummy auth',
        'users': {
            'Test': '123',
            'Foo': 'bar'
        }
    },
    'github': github_config
}


multiauth.initialize(app)


@app.route('/')
def index():
    return render_template('index.html', multiauth=multiauth)


if __name__ == '__main__':
    app.run('0.0.0.0', 10500, use_evalex=False)
