# The Database Model

# FFS, flask sqlalchemy has an issue with classes that use camelcase or underscores. i imagine there's a sanitization
# that happens in the sqlalchemy library that flask doesn't f with. Don't spend an hour trying to debug
# message_types as a model class...

import datetime
import hashlib
import os
import uuid

from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.rbac import RoleMixin
from flask import g
from sqlalchemy_utils import UUIDType
from sqlalchemy_utils import JSONType
from sqlalchemy_utils import force_auto_coercion

force_auto_coercion()

from webapp import application

db = SQLAlchemy(application)

roles_parents = db.Table(
    'roles_parents',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id')),
    db.Column('parent_id', db.Integer, db.ForeignKey('role.id'))
)

users_roles = db.Table(
    'users_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('parent_id', db.Integer, db.ForeignKey('role.id'))
)

orgs_parents = db.Table(
    'orgs_parents',
    db.Column('org_id', db.Integer, db.ForeignKey('org.id')),
    db.Column('org_parent_id', db.Integer, db.ForeignKey('org.id'))
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash_id = db.Column(db.String(64), default=lambda: hashlib.sha256(str(os.urandom(256))).hexdigest(),
                        unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=False)
    password = db.Column(db.String(80), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    team = db.relationship('Team', foreign_keys=team_id)
    secure_id = db.Column(db.String(80), nullable=True)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    user_guid = db.Column(UUIDType(binary=False), nullable=False, default=uuid.uuid4)

    def __init__(self, hash_id='', username='', email='', password='', secure_id=None, first_name='', last_name='',
                 user_guid=None, team_id=None):
        self.hash_id = hash_id
        self.username = username
        self.email = email
        self.password = password
        self.secure_id = secure_id
        self.first_name = first_name
        self.last_name = last_name
        self.user_guid = user_guid
        self.team_id = team_id

    def __repr__(self):
        return self.username

    def as_json(self):
        user_dict = {
            "id": self.id,
            "username": self.username,
            "user_guid": self.user_guid,
        }
        if self.email is not None:
            user_dict["email"] = self.email
        if self.first_name is not None:
            user_dict["first_name"] = self.first_name
        if self.last_name is not None:
            user_dict["last_name"] = self.last_name
        if self.team is not None:
            user_dict["teams"] = [team for team in self.team]
        return user_dict


class Api_Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', foreign_keys=user_id)
    api_key = db.Column(db.String(64), unique=True, nullable=False)
    secret_key = db.Column(db.String(128), nullable=False)

    def __init__(self, user='', api_key='', secret_key=''):
        self.user = user
        self.api_key = api_key
        self.secret_key = secret_key

    def __repr__(self):
        return self.api_key

    def get_user_by_key(key):
        user_key = Api_Key.query.filter_by(api_key=key).first()
        if user_key is None:
            return None
        return user_key.user

    def get_secret_by_key(key):
        user_key = Api_Key.query.filter_by(api_key=key).first()
        if user_key is None:
            return None
        return user_key.secret_key

    def as_json(self):
        api_key_dict = {
            "id": self.id,
            "user_id": self.user_id,
            "api_key": self.api_key,
            "secret_key": self.secret_key,
        }
        return api_key_dict


class Pub_Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', foreign_keys=user_id)
    pub_key = db.Column(db.String(128), unique=True, nullable=False)
    priv_key = db.Column(db.String(128), unique=True, nullable=True)

    def __init__(self, user='', pub_key='', priv_key=None):
        self.user = user
        self.pub_key = pub_key
        self.priv_key = priv_key

    def __repr__(self):
        # show beginning of hash of pub key
        return hashlib.sha256(self.pub_key).hexdigest()[:20]

    def get_user_by_key(key):
        user_key = Pub_Key.query.filter_by(pub_key=key).first()
        if user_key is None:
            return None
        return user_key.user


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def __init__(self, name=''):
        self.name = name

    def __repr__(self):
        return self.name

    @staticmethod
    def get_by_name(name):
        return Team.query.filter_by(name=name).first()

    def as_json(self):
        team_dict = {
            'name': self.name,
            'id': self.id
        }
        return team_dict


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    parents = db.relationship(
        'Role',
        secondary=roles_parents,
        primaryjoin=(id == roles_parents.c.role_id),
        secondaryjoin=(id == roles_parents.c.parent_id),
        backref=db.backref('children', lazy='dynamic')
    )

    def __init__(self, name=''):
        RoleMixin.__init__(self)
        self.name = name

    def __repr__(self):
        return self.name

    def add_parent(self, parent):
        self.parents.append(parent)

    def add_parents(self, *parents):
        for parent in parents:
            self.add_parent(parent)

    @staticmethod
    def get_by_name(name):
        return Role.query.filter_by(name=name).first()

    def as_json(self):
        role_dict = {
            'name': self.name,
            'id': self.id
        }
        return role_dict


class Org(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    parents = db.relationship(
        'Org',
        secondary=orgs_parents,
        primaryjoin=(id == orgs_parents.c.org_id),
        secondaryjoin=(id == orgs_parents.c.org_parent_id),
        backref=db.backref('children', lazy='dynamic')
    )

    def __init__(self, name=''):
        self.name = name

    def __repr__(self):
        return self.name

    def add_parent(self, parent):
        self.parents.append(parent)

    def as_json(self):
        org_dict = {
            "id": self.id,
            "name": self.name,
        }
        return org_dict


class Portfolio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=False, nullable=False)
    org_id = db.Column(db.Integer, db.ForeignKey('org.id'), nullable=False)
    org = db.relationship('Org', foreign_keys=org_id)

    def __init__(self, name='', org=''):
        self.name = name
        self.org = org

    def __repr__(self):
        return self.name

    def as_json(self):
        portfolio_dict = {
            "id": self.id,
            "name": self.name,
            "org_id": self.org.id
        }
        return portfolio_dict


def get_current_user():
    # TODO: client key signing will do a username lookup
    username = g.get('username', 'guest')
    return User.query.filter_by(username=username).first()
