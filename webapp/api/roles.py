from flask import request, jsonify
from flask.views import MethodView
from webapp.model import User, Role
#from webapp import rbac
from webapp.model import db


class Roles(MethodView):
    """
    endpoint for viewing roles
    Get /roles/: returns all role names and id's
    Get /roles/<role_id>: returns role name
    """
    #decorators = [rbac.allow(['api'], ['GET', ])]

    def get(self, role_id=None):
        if role_id is None:
            roles = Role.query.all()
            role_list = [r.as_json() for r in roles]
            return jsonify(roles=role_list)
        else:
            role = Role.query.filter_by(id=role_id).first()
            role_json = role.as_json()
            return jsonify(role_json)


class UserRoles(MethodView):
    """
    endpoint for manipulating user roles and user privileges
    Get /roles/<user_id>: returns roles associated with user
    Post /roles/<user_id>: requires: {action:<add,remove>, role_name:name}
    """
    decorators = [rbac.allow(['api'], ['GET', 'POST'])]

    def get(self, user_id=None):
        if user_id is None:
            roles = Role.query.all()
            role_list = [r.as_json() for r in roles]
            return jsonify(roles=role_list)
        else:
            user = User.query.filter_by(id=user_id).first()
            if user is None:
                return jsonify(error="user not found"), 404
            role_list = [r.as_json() for r in user.roles]
            return jsonify(user_roles=role_list)

    def post(self, user_id=None):
        if user_id is None:
            return jsonify(error="user_id required"), 404
        user = User.query.filter_by(id=user_id).first()
        if user is None:
            return jsonify(error="user not found"), 404
        role_name = request.json.get('role_name', '')
        role = Role.query.filter_by(name=role_name).first()
        if role is None:
            return jsonify(error="required field role invalid"), 400
        action = request.json.get('action', '')
        if action == 'add':
            user.add_role(role)
        elif action == 'remove':
            user.del_role(role)
        else:
            return jsonify(error="required field action invalid"), 400
        role_list = [r.as_json() for r in user.roles]
        db.session.add(user)
        db.session.commit()
        return jsonify(user_roles=role_list), 201
