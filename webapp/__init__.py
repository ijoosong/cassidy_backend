import xmlrpclib
from flask import Flask
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask.ext.rbac import RBAC
from flask_swagger import swagger
from flask.ext.cors import CORS
from config import db_config
import os

try:
    from config import options
except ImportError:
    options = {}

application = Flask(__name__)
CORS(application)

application.config.update(
    RBAC_USE_WHITE=options.get('rbacEnabled', True),
)

# DB Connection Information
application.config['SQLALCHEMY_DATABASE_URI'] = \
    'postgres://' + db_config['dbuser'] + ':' + \
    db_config['dbpass'] + '@' + \
    db_config['dbhost'] + '/' + \
    db_config['dbname']

application.config.update(
    RBAC_USE_WHITE=options.get('rbacEnabled', True),
)

from webapp.model import *

# register logging before RBAC so logs work when rbac denies access
from webapp import logs

admin = Admin(application, name='Admin')

admin.add_view(ModelView(Role, db.session))
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Api_Key, db.session))
admin.add_view(ModelView(Org, db.session))
admin.add_view(ModelView(Portfolio, db.session))

# set custom server header
@application.after_request
def rem_serv_header(response):
    response.headers['Server'] = "Bankchain"
    return response

from webapp import auth

# RBAC SETUP

rbac = RBAC(application)
"""
rbac.set_role_model(Role)
rbac.set_user_model(User)
rbac.set_user_loader(get_current_user)
"""

# Create roles:
try:
    req_roles = ['all', 'search', 'user']
    roles = Role.query.all()
    for r in req_roles:
        if r not in [a.name for a in roles]:
            r1 = Role(r)
            db.session.add(r1)
            db.session.commit()
    req_users = ['guest']
    users = User.query.all()
    for u in req_users:
        if u not in [a.username for a in users]:
            u1 = User(
                hash_id=hashlib.sha256(str(os.urandom(256))).hexdigest(),
                username='guest',
                email='none'
            )
            all_role = Role.query.filter_by(name='all').first()
            u1.add_role(all_role)
            db.session.add(u1)
            db.session.commit()
except Exception as e:
    print "DB not ready, or role/user models have changed"
    print e

from api import api
application.register_blueprint(api, url_prefix='/api/v1')
docs = swagger(application)

from webapp import middleware
from webapp import website



