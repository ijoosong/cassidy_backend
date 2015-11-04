import base64

from flask import redirect, flash

try:
    from config import options
except ImportError:
    options = {}


def load_user_data(u):
    user_data = {}
    user_data['username'] = u.username
    user_data['fname'] = u.first_name
    user_data['lname'] = u.last_name
    user_data['email'] = u.email
    user_data['user_id'] = u.id
    user_data['hash_id'] = u.hash_id
    user_data['userguid'] = u.user_guid
    sec2fa = u.secure_id
    if sec2fa is None:
        user_data['sec'] = False
    else:
        user_data['sec'] = True
    return user_data


def make_qr_code_img(text):
    import qrcode
    import StringIO
    qr = qrcode.QRCode()
    qr.add_data(text)
    qr.make()
    img = qr.make_image()
    output = StringIO.StringIO()
    img.save(output, 'GIF')
    data = 'data:image/png;base64,' + base64.b64encode(output.getvalue())
    output.close()
    img = None
    return data


def flash_redirect(message, path='/'):
    flash(message)
    return redirect(path)
