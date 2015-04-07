# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import os

from flask import Flask, render_template, flash, session, url_for, redirect, request
from flask_multiauth import MultiAuth


app = Flask(__name__)
app.debug = True
app.secret_key = 'fma-example'
multiauth = MultiAuth()

github_oauth_config = {
    'consumer_key': os.environ['MULTIAUTH_GITHUB_CLIENT_ID'],
    'consumer_secret': os.environ['MULTIAUTH_GITHUB_CLIENT_SECRET'],
    'request_token_params': {'scope': 'user:email'},
    'base_url': 'https://api.github.com',
    'request_token_url': None,
    'access_token_method': 'POST',
    'access_token_url': 'https://github.com/login/oauth/access_token',
    'authorize_url': 'https://github.com/login/oauth/authorize'
}

app.config['WTF_CSRF_ENABLED'] = False
app.config['MULTIAUTH_LOGIN_FORM_TEMPLATE'] = 'login_form.html'
app.config['MULTIAUTH_LOGIN_SELECTOR_TEMPLATE'] = 'login_selector.html'
app.config['MULTIAUTH_USER_INFO_KEYS'] = ['email', 'name', 'affiliation']
app.config['MULTIAUTH_AUTH_PROVIDERS'] = {
    'test': {
        'type': 'static',
        'title': 'Insecure dummy auth',
        'users': {
            'Test': '123',
            'Foo': 'bar'
        }
    },
    'github': {
        'type': 'oauth',
        'title': 'GitHub',
        'oauth': github_oauth_config
    }
}
app.config['MULTIAUTH_USER_PROVIDERS'] = {
    'test': {
        'type': 'static',
        'users': {
            'Test': {'email': 'test@example.com', 'name': 'Guinea Pig'},
            'Somebody': {'email': 'somebody@example.com', 'name': 'Some Body'}
        }
    },
    'github': {
        'type': 'oauth',
        'oauth': github_oauth_config,
        'endpoint': '/user',
        'identifier_field': 'id',
        'mapping': {
            'affiliation': 'company'
        }
    }
}
app.config['MULTIAUTH_PROVIDER_MAP'] = {
    'test': 'test',
    'github': [
        {
            'user_provider': 'github'
        }
    ]
}


def save_user_in_session(user):
    session['user_identifier'] = user.identifier
    session['user_refresh_data'] = user.refresh_data
    session['user_email'] = user.data['email']


@multiauth.user_handler
def user_handler(user):
    session['logged_in'] = True
    save_user_in_session(user)
    flash('Received UserInfo: {}'.format(user), 'success')


@app.route('/')
def index():
    results = None
    if 'search' in request.args:
        exact = 'exact' in request.args
        criteria = {}
        if request.args['email']:
            criteria['email'] = request.args['email']
        if request.args['name']:
            criteria['name'] = request.args['name']
        results = list(multiauth.search_users(exact=exact, **criteria))
    return render_template('index.html', results=results)


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('index'))


@app.route('/refresh')
def refresh():
    user = multiauth.refresh_user(session['user_identifier'], session['user_refresh_data'])
    save_user_in_session(user)
    flash('Refreshed UserInfo: {}'.format(user), 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    multiauth.init_app(app)
    app.run('0.0.0.0', 10500, use_evalex=False)
