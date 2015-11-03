from flask import render_template, flash, redirect
from app import app
from .forms import LoginForm


@app.route('/')
@app.route('/index/')
def index():
    user = {'name': 'Zach'}
    tweets = [
        {
            'username': 'ijoosong',
            'message': 'Lol is this thing working?'
        },
        {
            'username': 'inpursuitofswag',
            'message': 'lawlz you aint know crap'
        }
    ]
    return render_template('index.html', title='Home', user=user, tweets=tweets)

@app.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    return render_template('login.html', title='Sign In', form=form, providers=app.config['OPENID_PROVIDERS'])
