# This file is part of Flask-MultiAuth.
# Copyright (C) 2015 CERN
#
# Flask-MultiAuth is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

from __future__ import unicode_literals

import json
import os

from flask import Flask, render_template, flash, session, url_for, redirect, request, g
from flask_sqlalchemy import SQLAlchemy

from flask_multiauth import MultiAuth
from flask_multiauth.providers.sqlalchemy import SQLAlchemyAuthProviderBase, SQLAlchemyUserProviderBase


app = Flask(__name__)
app.debug = True
app.secret_key = 'fma-example'
db = SQLAlchemy()
multiauth = MultiAuth()


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    email = db.Column(db.String)
    affiliation = db.Column(db.String)


class Identity(db.Model):
    __tablename__ = 'identities'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    provider = db.Column(db.String)
    identifier = db.Column(db.String)
    multiauth_data = db.Column(db.Text)
    password = db.Column(db.String)
    user = db.relationship(User, backref='identities')


class LocalAuthProvider(SQLAlchemyAuthProviderBase):
    type = 'local'
    identity_model = Identity
    provider_column = Identity.provider
    identifier_column = Identity.identifier

    def check_password(self, identity, password):
        return identity.password == password


class LocalUserProvider(SQLAlchemyUserProviderBase):
    type = 'local'
    user_model = User
    identity_user_relationship = Identity.user


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

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/multiauth.db'
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
    },
    'local': {
        'type': LocalAuthProvider,
        'title': 'Local Accounts'
    }
}
app.config['MULTIAUTH_USER_PROVIDERS'] = {
    'test': {
        'type': 'static',
        'users': {
            'Test': {'email': 'test@example.com', 'name': 'Guinea Pig'},
            'Somebody': {'email': 'somebody@example.com', 'name': 'Some Body'}
        },
        'groups': {
            'Admins': ['Test'],
            'Everybody': ['Test', 'Somebody'],
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
    },
    'local': {
        'type': LocalUserProvider,
    }
}
app.config['MULTIAUTH_PROVIDER_MAP'] = {
    'local': 'local',
    'test': 'test',
    'github': [
        {
            'user_provider': 'github'
        }
    ]
}


@multiauth.user_handler
def user_handler(user_info):
    identity = Identity.query.filter_by(provider=user_info.provider.name, identifier=user_info.identifier).first()
    if not identity:
        user = User.query.filter_by(email=user_info.data['email']).first()
        if not user:
            user = User(**user_info.data)
            db.session.add(user)
        identity = Identity(provider=user_info.provider.name, identifier=user_info.identifier)
        user.identities.append(identity)
    else:
        user = identity.user
    identity.multiauth_data = json.dumps(user_info.multiauth_data)
    db.session.commit()
    session['user_id'] = user.id
    flash('Received UserInfo: {}'.format(user_info), 'success')


@app.before_request
def load_user_from_session():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])


@app.route('/')
def index():
    results = None
    if request.args.get('search') == 'users':
        exact = 'exact' in request.args
        criteria = {}
        if request.args['email']:
            criteria['email'] = request.args['email']
        if request.args['name']:
            criteria['name'] = request.args['name']
        results = list(multiauth.search_users(exact=exact, **criteria))
    elif request.args.get('search') == 'groups':
        exact = 'exact' in request.args
        results = list(multiauth.search_groups(exact=exact, name=request.args['name']))
    return render_template('index.html', results=results)


@app.route('/group/<provider>/<name>/')
def group(provider, name):
    group = multiauth.get_group(provider, name)
    if group is None:
        flash('No such group', 'error')
        return redirect(url_for('index'))
    return render_template('group.html', group=group)


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('index'))


@app.route('/refresh')
def refresh():
    if not g.user:
        flash('Not logged in', 'error')
        return redirect(url_for('index'))
    for identity in g.user.identities:
        if json.loads(identity.multiauth_data) is None:
            continue
        user_info = multiauth.refresh_user(identity.identifier, json.loads(identity.multiauth_data))
        identity.multiauth_data = json.dumps(user_info.multiauth_data)
        flash('Refreshed UserInfo: {}'.format(user_info), 'success')
    db.session.commit()
    return redirect(url_for('index'))


def main():
    multiauth.init_app(app)
    db.init_app(app)
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(name='Local Guinea Pig').count():
            user = User(name='Local Guinea Pig', email='test@example.com', affiliation='Local')
            identity = Identity(provider='local', identifier='Test', multiauth_data='null', password='123')
            user.identities.append(identity)
            db.session.add(user)
            db.session.commit()
    app.run('0.0.0.0', 10500, use_evalex=False)


if __name__ == '__main__':
    main()
