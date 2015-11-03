import os
basedir = os.path.abspath(os.path.dirname(__file__))

db_info = {
    'user': 'joe',
    'password': 'qwe123',
    'host': 'localhost',
    'db_name': 'twitteranalytics',
}

SQLALCHEMY_DATABASE_URI = "postgresql://" + \
                          db_info[user] + ":" + \
                          db_info[password] + "@" + \
                          db_info[host] + "/" + \
                          db_info[db_name]

SQLALCHEMY_MIGRATE_REPO = os.path.join(basedir, 'db_repository')


WTF_CSRF_ENABLED = True
SECRET_KEY = 'password'

OPENID_PROVIDERS = [
    {'name': 'Google', 'url': 'https://www.google.com/accounts/o8/id'},
    {'name': 'Yahoo', 'url': 'https://me.yahoo.com'},
    {'name': 'AOL', 'url': 'http://openid.aol.com/<username>'},
    {'name': 'Flickr', 'url': 'http://www.flickr.com/<username>'},
    {'name': 'MyOpenID', 'url': 'https://www.myopenid.com'}]


