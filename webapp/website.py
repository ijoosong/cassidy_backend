import hashlib
import random
import base64
import uuid

from flask import render_template, request, session, redirect, jsonify
import bcrypt
from otpauth import OtpAuth

from webapp import application, rbac, docs
from webapp.model import User, Role
from webapp.model import db
from webapp import helper
from webapp.helper import flash_redirect

try:
    from config import options
except ImportError:
    options = {}


@application.route('/')
@rbac.allow(['all'], ['GET'])
def root():
    return render_template('index.html', pageTitle='Bankchain')


@application.route('/ping')
@rbac.exempt
def ping():
    return 'ok'


@application.route('/signup')
@rbac.allow(['all'], ['GET'])
def signup_user():
    return render_template('signup.html', pageTitle='Signup User')


@application.route('/signup', methods=['POST'])
@rbac.allow(['all'], ['POST'])
def signup():
    un = request.form.get('username', 'guest')
    user = User.query.filter_by(username=un).first()
    pw = str(request.form.get('password', ''))
    if user is not None:
        return flash_redirect('Username Taken')
    pw_hash = bcrypt.hashpw(pw, bcrypt.gensalt(14))
    fname = request.form.get('fname', '')
    lname = request.form.get('lname', '')
    em = request.form.get('email', '')
    hash_id = hashlib.sha256(str(random.getrandbits(256))).hexdigest()
    user_guid = uuid.uuid4()

    u = User(username=un, email=em, password=pw_hash, secure_id=None, first_name=fname, last_name=lname,
             hash_id=hash_id, user_guid=user_guid)
    # add all role to any user
    r_all = Role.query.filter_by(name='all').first()
    r_user = Role.query.filter_by(name='user').first()
    r_userAdmin = Role.query.filter_by(name='userAdmin').first()
    r_mcs = Role.query.filter_by(name='mcs').first()
    u.add_role(r_all)
    u.add_role(r_user)
    u.add_role(r_userAdmin)
    u.add_role(r_mcs)
    db.session.add(u)
    db.session.commit()
    return redirect('/')


@application.route('/login', methods=['POST'])
@rbac.allow(['all'], ['POST'])
def login():
    un = request.form.get('username', 'guest')
    pw = request.form.get('password', '')
    sec = request.form.get('secureid', '')
    user = User.query.filter_by(username=un).first()
    if user is None:
        application.l.info('User not found')
        return flash_redirect('Permission Denied')
    else:
        check_pass = bcrypt.hashpw(str(pw), str(user.password))
        if check_pass == user.password:
            if not options.get('secureIdDisabled', False) and user.secure_id is not None:
                application.l.debug('Secure_ID not Null, verifying secureID value')
                auth = OtpAuth(user.secure_id)
                if not auth.valid_totp(sec):
                    application.l.info('Secure_ID invalid')
                    return flash_redirect('Permission Denied')
            return redirect('/MCS/select_trade')
        else:
            application.l.info('Password invalid')
            return flash_redirect('Permission Denied')
    return redirect('/')


@application.route('/logout', methods=['GET'])
@rbac.allow(['user'], ['GET'])
def logout():
    return flash_redirect('Successfully Logged Out')


@application.route('/user')
@rbac.allow(['user'], ['GET'])
def user_profile():
    user = User.query.filter_by(username=username).first()
    user_data = helper.load_user_data(user)
    return render_template('user.html', pageTitle='User Profile', user_data=user_data)


@application.route('/user/<int:uid>/2fa/<action>')
@rbac.allow(['user'], ['GET'])
def manage_2fa(uid, action):
    user = User.query.filter_by(id=uid).first()
    if action not in ['enable', 'disable']:
        return flash_redirect('Unknown Action')
    elif action == 'enable':
        sec_enable = True
    elif action == 'disable':
        sec_enable = False
    user_data = helper.load_user_data(user)
    user_2fa_secret = base64.b32encode(hashlib.sha256(str(random.getrandbits(256))).digest())[:32]
    auth = OtpAuth(user_2fa_secret)
    user_2fa_uri = auth.to_uri('totp', 'Bankchain.' + user.email, 'Bankchain')
    img = helper.make_qr_code_img(user_2fa_uri)
    return render_template('2fa.html', pageTitle='Manage 2FA', user_data=user_data, img=img, sec_enable=sec_enable)


@application.route('/user/<int:uid>/2fa/<action>', methods=['POST'])
@rbac.allow(['user'], ['POST'])
def change_2fa(uid, action):
    user = User.query.filter_by(id=uid).first()
    if action != session.get('2fa_action', 'none') or action not in ['enable', 'disable']:
        return flash_redirect('Unknown Action')
    sec_code = request.form.get('sec', 'none')
    if action == 'enable':
        user_2fa_secret = session.get('2fa_secret', 'none')
    elif action == 'disable':
        user_2fa_secret = user.secure_id
    if user_2fa_secret == 'none' or sec_code == 'none':
        return flash_redirect('Unknown Error')
    auth = OtpAuth(user_2fa_secret)
    if auth.valid_totp(sec_code):
        if action == 'enable':
            user.secure_id = user_2fa_secret
            db.session.commit()
        elif action == 'disable':
            user.secure_id = None
            for r in user.roles:
                if r.name not in ['all', 'user']:
                    user.del_role(r)
            db.session.commit()
    else:
        return flash_redirect('Invalid Code')
    return redirect('/user')


@application.route('/users/<int:uid>/<action>/<rolename>', methods=['GET'])
@rbac.allow(['userAdmin'], ['GET'])
def user_action_role(uid, action, rolename):
    user = User.query.filter_by(id=uid).first()
    if user is None:
        return "User not found"
    if user.username == 'guest':
        return flash_redirect('Changing guest roles not allowed.', '/Users/')
    role = Role.query.filter_by(name=rolename).first()
    if role is None:
        return "Role not found"
    if action == 'addrole':
        user.add_role(role)
    elif action == 'delrole':
        user.del_role(role)
    else:
        return "Action not found"
    db.session.commit()
    return redirect('/Users/')


@application.route('/docs')
@rbac.exempt
def swagger():
    return jsonify(docs)

# @application.route('/s')
# @rbac.exempt
# def show():
#     return application.send_static_file('../swagger-ui/dist/index.html')

