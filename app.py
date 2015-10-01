import os
import base64
from io import StringIO
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

# create application instance
app = Flask(__name__)
app.config.from_object('config')

# initialize extensions
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)

def generateToken():
    return 123456

def sendToken():
    print 'Use twilio API'

class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    phone = db.Column(db.String(64))
    method = db.Column(db.String(16))

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

    return render_template('register.html', form=form)

@app.route('/verification', methods=['GET', 'POST'])
def verification():
    """two factor auth route."""
    if current_user.is_authenticated():
        # if user is logged in we check the token
        form = TwoFactorForm()
        if form.validate_on_submit():
       	    if session['token'] == form.token.data:
                # log user in
                login_user(user)
                flash('You are now logged in!')
                return redirect(url_for('index'))
            flash('Invalid username, password or token.')
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
            flash('Invalid username, password or token.')
            return redirect(url_for('login'))
        # redirect to the two-factor auth page, passing token in the session
        session['code'] = generateToken()
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
