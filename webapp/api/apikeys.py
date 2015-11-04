from flask import request, jsonify
from flask.views import MethodView
from webapp.model import User, Api_Key
from webapp import rbac
from webapp.model import db
from sqlalchemy.exc import IntegrityError


class Api_Keys(MethodView):
    """
    endpoint for manipulating user api keys
    Post Data: key, secret, user_id
    Get Values: key, secret, user_id
    """
    decorators = [rbac.allow(['api'], ['GET', 'POST'])]

    def get(self, user_id=None):
        """
        This is the endpoint that returns the user api keys
        """
        if user_id is None:
            return jsonify(error="Need to put in user_id"), 404
        api_keys = Api_Key.query.filter_by(user_id=user_id).all()
        if len(api_keys) == 0:
            return jsonify(error="no api keys found under user"), 400
        data = [ak.as_json() for ak in api_keys]
        return jsonify(api_keys=data)

    def post(self, user_id=None):
        """
        This function creates an api key for a user
        """
        if user_id is None:
            return jsonify(error="Need to put in user_id"), 404
        api_key = request.json.get("key", None)
        secret_key = request.json.get("secret", None)
        print "it definitely comes here i think \n\n\n\n"
        if None in [api_key, secret_key]:
            print "does it even get here? \n\n\n\n\n\n"
            return jsonify(error="key and secret parameters required"), 400
        try:
            u = User.query.filter_by(id=user_id).first()
            a = Api_Key(user=u, api_key=api_key, secret_key=secret_key)
            db.session.add(a)
            db.session.commit()
        except IntegrityError as e:
            # error code for unique constraint violation
            if e.orig.pgcode == "23505":
                return jsonify(error='api keys must be unique'), 400
            else:
                return jsonify(error='unknown'), 500
        else:
            return jsonify(api_key=a.as_json()), 201

