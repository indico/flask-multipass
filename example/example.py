# This file is part of Flask-Multipass.
# Copyright (C) 2015 - 2021 CERN
#
# Flask-Multipass is free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.

import json

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy

from flask_multipass import Multipass
from flask_multipass.providers.sqlalchemy import SQLAlchemyAuthProviderBase, SQLAlchemyIdentityProviderBase

application = app = Flask(__name__)
app.debug = True
app.secret_key = 'fma-example'
db = SQLAlchemy()
multipass = Multipass()


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
    multipass_data = db.Column(db.Text)
    password = db.Column(db.String)
    user = db.relationship(User, backref='identities')

    @property
    def provider_impl(self):
        return multipass.identity_providers[self.provider]


class LocalAuthProvider(SQLAlchemyAuthProviderBase):
    identity_model = Identity
    provider_column = Identity.provider
    identifier_column = Identity.identifier

    def check_password(self, identity, password):
        return identity.password == password


class LocalIdentityProvider(SQLAlchemyIdentityProviderBase):
    user_model = User
    identity_user_relationship = Identity.user


@multipass.identity_handler
def identity_handler(identity_info):
    identity = Identity.query.filter_by(provider=identity_info.provider.name,
                                        identifier=identity_info.identifier).first()
    if not identity:
        user = User.query.filter_by(email=identity_info.data['email']).first()
        if not user:
            user = User(**identity_info.data.to_dict())
            db.session.add(user)
        identity = Identity(provider=identity_info.provider.name, identifier=identity_info.identifier)
        user.identities.append(identity)
    else:
        user = identity.user
    identity.multipass_data = json.dumps(identity_info.multipass_data)
    db.session.commit()
    session['user_id'] = user.id
    flash(f'Received IdentityInfo: {identity_info}', 'success')


@app.before_request
def load_user_from_session():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])


@app.route('/')
def index():
    results = None
    if request.args.get('search') == 'identities':
        exact = 'exact' in request.args
        criteria = {}
        if request.args['email']:
            criteria['email'] = request.args['email']
        if request.args['name']:
            criteria['name'] = request.args['name']
        results = list(multipass.search_identities(exact=exact, **criteria))
    elif request.args.get('search') == 'groups':
        exact = 'exact' in request.args
        results = list(multipass.search_groups(exact=exact, name=request.args['name']))
    return render_template('index.html', results=results)


@app.route('/group/<provider>/<name>/')
def group(provider, name):
    group = multipass.get_group(provider, name)
    if group is None:
        flash('No such group', 'error')
        return redirect(url_for('index'))
    return render_template('group.html', group=group)


@app.route('/logout')
def logout():
    flash('Logged out', 'success')
    return multipass.logout(url_for('index'), clear_session=True)


@app.route('/refresh')
def refresh():
    if not g.user:
        flash('Not logged in', 'error')
        return redirect(url_for('index'))
    for identity in g.user.identities:
        if json.loads(identity.multipass_data) is None:
            continue
        identity_info = multipass.refresh_identity(identity.identifier, json.loads(identity.multipass_data))
        identity.multipass_data = json.dumps(identity_info.multipass_data)
        flash(f'Refreshed IdentityInfo: {identity_info}', 'success')
    db.session.commit()
    return redirect(url_for('index'))


app.config.from_pyfile('example.cfg')
multipass.register_provider(LocalAuthProvider, 'example_local')
multipass.register_provider(LocalIdentityProvider, 'example_local')
multipass.init_app(app)
db.init_app(app)
with app.app_context():
    db.create_all()
    if not User.query.filter_by(name='Local Guinea Pig').count():
        user = User(name='Local Guinea Pig', email='test@example.com', affiliation='Local')
        identity = Identity(provider='local', identifier='Test', multipass_data='null', password='123')
        user.identities.append(identity)
        db.session.add(user)
        db.session.commit()


if __name__ == '__main__':
    app.run('0.0.0.0', 10500, use_evalex=False)
