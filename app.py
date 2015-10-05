import os
import base64
from flask import Flask, render_template, redirect, url_for, flash, session, \
    abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin, login_user, logout_user, \
    current_user
from flask.ext.bootstrap import Bootstrap
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import Required, Length, EqualTo
from random import randint
from twilio.rest import TwilioRestClient
import twilio

# create application instance
app = Flask(__name__)
app.config.from_object('config')

# initialize extensions
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)


# Send the token via SMS or Voice depending of the user preferred method
def sendToken(username, token):
    user = User.query.filter_by(username=username).first()
    client = TwilioRestClient()
    if user.method == 'SMS':
        try:
            message = client.messages.create(
            body="Your token is:" + str(token),  # Use the token to complete login
            to=user.phone,
            from_= app.config['PHONE_NUMBER'],
            )
	    flash('Token sent with success !!')
	except twilio.TwilioRestException as e:
            print e
	    flash(u'Error while sending the token', 'error')
    elif user.method == 'Voice':
            try:
                call = client.calls.create(to=user.phone, from_=app.config['PHONE_NUMBER'],
                           url="http://twimlets.com/message?Message%5B0%5D=Your%20token%20is%20"+str(token)+"&")
                flash('Token sent with success !!')
            except twilio.TwilioRestException as e:
    		print e
		flash(u'Error while sending the token', 'error')

# TODO Generate more secure token
def generateToken():
    #return randint(100000, 999999)
    return "123456"


class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    phone = db.Column(db.String(64))
    method = db.Column(db.String(16))
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class RegisterForm(Form):
    """Registration form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    password_again = PasswordField('Password again',
                                   validators=[Required(), EqualTo('password')])
    phone = StringField('Phone', validators=[Required(), Length(1, 64)])
    method = RadioField('Preferred method:', choices=[('SMS','You will receice the code in SMS'),('Voice','You will receive the code in a Call')])
    submit = SubmitField('Register')


class LoginForm(Form):
    """Login form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Login')

class TwoFactorForm(Form):
    """Verification code form."""
    token = StringField('Token', validators=[Required(), Length(6, 6)])
    submit = SubmitField('Verification')


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/voice')
def voice():
    return render_template('call.xml')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('register'))
        # add new user to the database
        user = User(username=form.username.data, password=form.password.data, phone=form.phone.data, method=form.method.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('register.html', form=form)

# TODO Limit the number of false request (brute force prevention)
@app.route('/verification', methods=['GET', 'POST'])
def verification():
    """two factor auth route."""
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = TwoFactorForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=session['username']).first()
       	if session['token'] == form.token.data:
            # log user in
            login_user(user)
            flash('You are now logged in!')
            return redirect(url_for('index'))
        flash(' Invalid token.')
        return redirect(url_for('verification'))
    return render_template('verification.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data):
            flash('Invalid username or  password')
            return redirect(url_for('login'))
        # redirect to the two-factor auth page, passing token in the session
        session['username'] = form.username.data
        session['token'] = generateToken()
        sendToken(session['username'], session['token'])
        return redirect(url_for('verification'))

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    """User logout route."""
    logout_user()
    return redirect(url_for('index'))


# create database tables if they don't exist yet
db.create_all()


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
