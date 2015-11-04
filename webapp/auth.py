import json
import hashlib
import base64
import hmac
import time

from flask import request, jsonify, abort, g

from webapp import application
from webapp.model import Api_Key

try:
    from config import options
except ImportError:
    options = {}


@application.errorhandler(401)
def authentication_error(error):
    return jsonify(error="authentication required"), 401


def verify_auth():
    if request.path.startswith('/api/'):
        auth_header = request.headers.get('X-Auth-Key', None)
        nonce = request.headers.get('X-Auth-Nonce', None)
        timestamp = request.headers.get('X-Auth-Timestamp', None)
        sig = request.headers.get('X-Auth-Sig', None)
        skip_auth = options.get('skipAuth', False)
        if options.get('testEnabled', False):
            testingMode = int(request.headers.get('X-Auth-TestingMode', 0))
            if testingMode == 1:
                skip_auth = True
        if not skip_auth:
            req_body = request.data
            if None in [auth_header, nonce, timestamp, sig]:
                return abort(401)
            if abs(int(time.time()) - int(timestamp)) > 60 * 5:
                return abort(401)
            if req_body == "":
                req_body = {}
            else:
                req_body = json.loads(req_body)
            body_str = json.dumps(req_body, sort_keys=True, separators=(',', ':'))
            Key = Api_Key.query.filter_by(api_key=auth_header).first()
            if Key is None:
                return abort(401)
            message = ''.join([str(auth_header), str(nonce), str(timestamp), body_str, request.path])
            hash_digest = hashlib.sha256(message).digest()
            hmac_digest = hmac.new(str(Key.secret_key), hash_digest, hashlib.sha512).digest()
            g.username = Key.user.username
            if not base64.b64encode(hmac_digest) == sig:
                abort(401)


@application.before_request
def auth_check():
    auth_required = options.get('authRequired', True)
    if auth_required:
        verify_auth()

