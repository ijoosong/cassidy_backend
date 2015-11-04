import requests
import time
import hmac
import base64
import json
import hashlib


key = 'test'
secret = 'a'
path = '/api/v1/transaction_types/'
body = {"name": "testing2"}
timestamp = int(time.time())
nonce = 1

body_str = json.dumps(body, sort_keys=True, separators=(',', ':'))

message = ''.join([str(key), str(nonce), str(timestamp), body_str, path])
hash_digest = hashlib.sha256(message).digest()
hmac_digest = hmac.new(str(secret), hash_digest, hashlib.sha512).digest()
sig = base64.b64encode(hmac_digest)

headers = {
    'X-Auth-Key': key,
    'X-Auth-Nonce': nonce,
    'X-Auth-Sig': sig,
    'X-Auth-Timestamp': timestamp,
    'Content-Type': 'application/json',
}

resp = requests.post('http://localhost:5000%s' % path, json=body, headers=headers)
print resp.json()

