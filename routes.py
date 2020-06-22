from slothapp01 import app
from slothapp01.forms import LoginForm
from flask import render_template, flash, redirect
from flask_login import current_user, login_user
from slothapp01.models import User, Letter
from flask_login import logout_user
from flask_login import login_required
from flask import request
from werkzeug.urls import url_parse
from slothapp01 import db
from slothapp01.forms import RegistrationForm
from flask import url_for
from datetime import datetime
from slothapp01.forms import EditProfileForm, LetterForm, EmptyForm
from sqlalchemy import desc
from app.forms import ResetPasswordRequestForm
from slothapp01.email import send_apssword_reset_email

@app.route('/', methods=['GET','POST'])
@app.route('/index', methods=['GET','POST'])
@login_required
def index():    
    letters = current_user.followed_letters(current_user)
    return render_template('index.html', title = 'In The Box', letters = letters, user = current_user)

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username =form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username= form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now my special friend')
        return redirect( url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    #sender = current_user
    letters = current_user.penpal_letters(username)
    form = EmptyForm()
    return render_template('user.html', user=user, letters=letters, form=form)

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)

@app.route('/write_letter', methods=['GET', 'POST'])
@login_required
def write_letter():
    form = LetterForm()
    if form.validate_on_submit():
        letter = Letter(recipient = form.recipient.data, body = form.body.data, user_id = current_user.id)
        db.session.add(letter)
        db.session.commit()
        flash('Your letter has been sent.')
        return redirect(url_for('write_letter'))
    return render_template('write_letter.html', title='Write Letter', form=form)

@app.route('/friend/<username>', methods=['POST'])
@login_required
def friend(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash('User {} not found.'.format(username))
            return redirect(url_for('index'))
        if user == current_user:
            flash('You cannot follow yourself!')
            return redirect(url_for('user', username=username))
        current_user.friend(user)
        db.session.commit()
        flash('You are following {}!'.format(username))
        return redirect(url_for('user', username=username))
    else:
        return redirect(url_for('index'))


@app.route('/unfriend/<username>', methods=['POST'])
@login_required
def unfriend(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash('User {} not found.'.format(username))
            return redirect(url_for('index'))
        if user == current_user:
            flash('You cannot unfollow yourself!')
            return redirect(url_for('user', username=username))
        current_user.unfriend(user)
        db.session.commit()
        flash('You are not following {}.'.format(username))
        return redirect(url_for('user', username=username))
    else:
        return redirect(url_for('index'))

#View function for reset password form
@app.route('/reset_password_request', methods=['GET','POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_apssword_reset_email(user)
        flash('Check your email for password reset instructions')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html', title='Reset Password', form=form)

