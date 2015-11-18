import hashlib
import random
import uuid
import base64
from flask import request, jsonify
from flask.views import MethodView
from otpauth import OtpAuth
import bcrypt
from webapp.model import User, Role
from webapp import rbac, application
from webapp.model import db
from config import options


class UserAdmin(MethodView):
    decorators = [rbac.allow(['api'], ['GET', 'POST', 'PUT'])]

    def get(self, user_id):
        """
        This is the endpoint that returns the user information and roles
        ---
        tags:
          - users
        responses:
          200:
            description: success
            schema:
              id: user_out
              properties:
                id:
                  type: integer
                  description: user id
                username:
                  type: string
                  description: username
                user_guid:
                  type: string
                  description: unique identifier for user
                email:
                  type: string
                  description: user email (if set)
                first_name:
                  type: string
                  description: users first name (if set)
                last_name:
                  type: string
                  description: users last name (if set)
        """
        # celery test
        # rq = tasks.hello.apply_async(args=["Get User"])
        # results = async_result.AsyncResult(str(rq))
        # print results.get()
        # rq = tasks.send_message_test.apply_async()
        # results = async_result.AsyncResult(str(rq))
        # print results.get()

        if user_id is None:
            users = User.query.all()
            user_list = [u.as_json() for u in users]
            return jsonify(users=user_list)
        else:
            user = User.query.filter_by(id=user_id).first()
            if user is None:
                return jsonify(error="user not found"), 404
            else:
                return jsonify(user=user.as_json())

    def post(self):
        """
        Create a new user
        ---
        tags:
          - users
        parameters:
          - in: body
            name: body
            schema:
              id: user_in
              required:
                - username
                - password
              properties:
                username:
                  type: string
                  description: username for user login
                password:
                  type: string
                  description: password for user login
                fname:
                  type: string
                  description: first name of user
                lname:
                  type: string
                  description: last name of user
                email:
                  type: string
                  description: email address of user
        responses:
          201:
            description: User created
            schema:
              id: user_out
          400:
            description: username taken
            schema:
              id: error
              properties:
                error:
                  type: string
                  description: description of error
        """
        # celery test
        # rq = tasks.hello.apply_asyc(args=["Post User"])
        # results = async_result.AsyncResult(str(rq))
        # print results.get()

        un = request.json.get('username', 'guest')
        user = User.query.filter_by(username=un).first()
        pw = str(request.json.get('password', ''))
        if user is not None:
            return jsonify(error='Username Taken'), 400
        if options.get('testEnabled', False):
            # less secure for testing - faster
            pw_hash = bcrypt.hashpw(pw, bcrypt.gensalt(4))
        else:
            pw_hash = bcrypt.hashpw(pw, bcrypt.gensalt(14))
        fname = request.json.get('fname', '')
        lname = request.json.get('lname', '')
        em = request.json.get('email', '')
        hash_id = hashlib.sha256(str(random.getrandbits(256))).hexdigest()
        user_guid = uuid.uuid4()
        team_id = request.json.get('team_id')

        u = User(username=un, email=em, password=pw_hash, secure_id=None, first_name=fname, last_name=lname,
                 hash_id=hash_id, user_guid=user_guid, team_id=team_id)
        db.session.add(u)
        db.session.commit()

        # Building out user to push out
        user = User.query.filter_by(username=un).first()
        return jsonify(user=user.as_json()), 201

    def put(self, user_id):
        """
        edit user information
        ---
        tags:
          - users
        parameters:
          - in: body
            name: body
            schema:
              id: user_in
        responses:
          201:
            description: User created
            schema:
              id: user_out
          404:
            description: user not found
            schema:
              id: error
        """
        # celery test
        # rq = tasks.hello.apply_asyc(args=["Put User"])
        # results = async_result.AsyncResult(str(rq))
        # print results.get()

        user = User.query.filter_by(id=user_id).first()
        if user is None:
            return jsonify(error="user not found"), 404
        else:
            updates = request.get_json()
            for key, value in updates.iteritems():
                if key == "password":
                    if options.get('testEnabled', False):
                        # less secure for testing - faster
                        pw_hash = bcrypt.hashpw(value, bcrypt.gensalt(4))
                    else:
                        pw_hash = bcrypt.hashpw(value, bcrypt.gensalt(14))
                    setattr(user, key, pw_hash)
                elif hasattr(user, key):
                    setattr(user, key, value)
        db.session.add(user)
        db.session.commit()
        # return user info
        return jsonify(user=user.as_json()), 201


class UserNew2FA(MethodView):
    """
    endpoint for manipulating user 2fa
    Post Data: 2fa code, 2fa secret
    Get Values: username, 2fa secret
    """
    decorators = [rbac.allow(['api'], ['GET', 'PUT'])]

    def get(self, user_id):
        """
        get user 2fa secret
        ---
        tags:
          - users 2fa
        responses:
          201:
            description: user 2fa secret
            schema:
              id: 2fa_out
              properties:
                username:
                  type: string
                  description: username for user
                twoFASecret:
                  type: integer
                  description: secret key for user
          404:
            description: user not found
            schema:
              id: error
        """

        if user_id is None:
            return jsonify(error="invalid user id"), 404
        user = User.query.filter_by(id=user_id).first()
        if user is None:
            return jsonify(error="invalid user"), 404
        user2fa_secret = base64.b32encode(hashlib.sha256(str(random.getrandbits(256))).digest())[:32]
        return jsonify(username=user.username, twoFASecret=user2fa_secret)

    def put(self, user_id):
        """
        This is the endpoint that creates the user 2fa
        ---
        tags:
          - users 2fa
        parameters:
          - in: body
            name: body
            schema:
              id: 2fa_in
              properties:
                twoFACode:
                  type: string
                  description: code for 2fa
                twoFASecret:
                  type: integer
                  description: secret key for user
        responses:
          201:
            description: user 2fa secret
            schema:
              id: success
              properties:
                success:
                  type: boolean
                  value: true
          400:
            description: invalid 2fa secret or code
            schema:
              id: error
          404:
            description: invalid user
            schema:
              id: error
        """
        if user_id is None:
            return jsonify(error="invalid user id"), 404
        user = User.query.filter_by(id=user_id).first()
        if user is None:
            return jsonify(error="invalid user"), 404
        user2fa_secret = request.json.get('twoFASecret', None)
        if not user2fa_secret:
            return jsonify(error="invalid 2fa secret"), 400
        user2fa_code = request.json.get('twoFACode', None)
        if user2fa_code is None:
            return jsonify(error="invalid 2fa code"), 400
        auth = OtpAuth(user2fa_secret)
        if auth.valid_totp(user2fa_code):
            user.secure_id = user2fa_secret
            db.session.commit()
            return jsonify(success=True), 201
        return jsonify(error="wrong code"), 400

