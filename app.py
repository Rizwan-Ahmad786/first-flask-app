from collections import UserString
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms import validators
from wtforms.validators import InputRequired, Email, Length, DataRequired, EqualTo, ValidationError
from datetime import datetime
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_manager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import asc

import os
import smtplib


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Hi_this_is_my_todo_task_app!'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")

ENV = 'local'

if ENV == 'local':
    app.debug = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:rizwan786@localhost/db_postgres'
else:
    app.debug = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://qjbgrgemhxpznn:4c2a1c3cd4933ab3fe29bb20fa6d06819f7fd69d8d2d312e00bb3d11e2736d69@ec2-34-193-112-164.compute-1.amazonaws.com:5432/d89v8ls5o6h015'


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Bootstrap(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'pythoncheck786@gmail.com'
app.config['MAIL_PASSWORD'] = 'python786'
mail = Mail(app)
bcrypt = Bcrypt(app)


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), index=True, unique=True)
    email = db.Column(db.String(200), index=True, unique=True)
    password = db.Column(db.String(200))
    todos = db.relationship('Todo', backref='author', lazy='dynamic')

    def get_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Todo(db.Model):
    __tablename__ = 'todo'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    des = db.Column(db.String(500))
    complete = db.Column(db.Boolean)
    datecreated = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class LoginForm(FlaskForm):
    username = StringField('User Name', validators=[
                           InputRequired(), Length(min=4, max=35)])
    password = PasswordField('Password', validators=[
                             InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegistrationForm(FlaskForm):
    username = StringField('User Name', validators=[
                           InputRequired(), Length(min=4, max=35)])
    email = StringField('Email', validators=[InputRequired(), Email(
        message='Invalid email'), Length(max=35)])
    password = PasswordField('Password', validators=[
                             InputRequired(), Length(min=8, max=80)])
    password2 = PasswordField('Repeat Password', validators=[
                              DataRequired(), EqualTo('password')])

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError(
                'That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError(
                'That email is taken. Please choose a different one.')


class AddTodo(FlaskForm):
    title = StringField('Title', validators=[
                        InputRequired(), Length(min=1, max=200)])
    des = StringField('Description', validators=[
                      InputRequired(), Length(min=1, max=500)])
    submit = SubmitField('Submit')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(
        message='Invalid email'), Length(max=35)])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError(
                'There is no account with that email. you must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[
                             InputRequired(), Length(min=8, max=80)])
    password2 = PasswordField('Repeat Password', validators=[
                              DataRequired(), EqualTo('password')])

    submit = SubmitField('Reset Password')


@app.route('/')
@app.route('/login', methods=['Get', 'POST'])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user is None or not bcrypt.check_password_hash(user.password, form.password.data):
                flash('Invalid username or password', 'danger')
                return redirect(url_for('login'))
            login_user(user, remember=form.remember.data)
            return redirect('uncomplete_todos')
    return render_template('login.html', form=form)


@app.route('/signup', methods=['Get', 'POST'])
def signup():
    form = RegistrationForm()
    if request.method == "POST":
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(
                form.password.data, method='sha256')
            newuser = User(username=form.username.data,
                           email=form.email.data, password=hashed_password)
            db.session.add(newuser)
            db.session.commit()
            flash('Your account has been created! You are able now to log in')
            return redirect('login')
    return render_template('signup.html', form=form)


@app.route('/add_todo', methods=['GET', 'POST'])
@login_required
def add_todo():
    form = AddTodo()
    if request.method == "POST":
        title = request.form['title']
        des = request.form['des']
        newtodo = Todo(title=title, des=des, complete=False,
                       user_id=current_user.id)
        db.session.add(newtodo)
        db.session.commit()
        return redirect('uncomplete_todos')
    else:
        return render_template('add_todo.html', form=form)


@app.route('/uncomplete_todos')
@login_required
def uncomplete_todos():
    uncomplete_todos = Todo.query.filter_by(
        user_id=current_user.id, complete=False).order_by(asc(Todo.id))
    return render_template('uncomplete_todos.html', uncomplete_todos=uncomplete_todos)


@app.route('/cancelonclick')
def cancelonclick():
    return redirect('uncomplete_todos')


@app.route('/set_complete_true/<int:id>', methods=['POST'])
@login_required
def set_complete_true(id):
    todo = Todo.query.get_or_404(id)
    if todo.author != current_user:
        abort(403)
    if request.method == "POST":
        data = Todo.query.filter_by(id=id).first()
        data.complete = True
        db.session.add(data)
        db.session.commit()
        return redirect('/uncomplete_todos')


@app.route('/completed_todos')
@login_required
def completed_todos():
    completed_todos = Todo.query.filter_by(
        user_id=current_user.id, complete=True).order_by(asc(Todo.id))
    return render_template('completed_todos.html', completed_todos=completed_todos)


@app.route('/updatetodo/<int:id>', methods=['POST'])
@login_required
def updatetodo(id):
    todo = Todo.query.get_or_404(id)
    if todo.author != current_user:
        abort(403)
    if request.method == 'POST':
        data = Todo.query.filter_by(id=id).first()
        if id == data.id and data.user_id == current_user.id and data.complete == False:
            title = request.form['title']
            des = request.form['des']
            data = Todo.query.filter_by(id=id).first()
            data.title = title
            data.des = des
            db.session.add(data)
            db.session.commit()
            flash('Your todo has been updated!', 'success')
            return redirect('/uncomplete_todos')
        flash("You cannot update unknown todo! ", 'danger')
        return redirect('/uncomplete_todos')


@app.route('/update/<int:id>', methods=['POST'])
@login_required
def update(id):
    todo = Todo.query.get_or_404(id)
    if todo.author != current_user:
        abort(403)
    form = AddTodo()
    if request.method == 'POST':
        data = Todo.query.filter_by(id=id).first()
        if id == data.id and data.user_id == current_user.id and data.complete == False:
            return render_template('/update.html', data=data, form=form)
    else:
        abort(404)


@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    todo = Todo.query.get_or_404(id)
    if todo.author != current_user:
        abort(403)
    if request.method == "POST":
        delete_todo = Todo.query.filter_by(id=id).first()
        db.session.delete(delete_todo)
        db.session.commit()
        return redirect(url_for('uncomplete_todos'))
    else:
        abort(404)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


def send_email(user):
    token = user.get_token()
    msg = Message('Password Reset Request',
                  recipients=[user.email], sender='noreplay@gmail.com')
    msg.body = f'''To reset your password, click the following link

    {url_for('reset_token', token=token, _external=True)}

    If you did not make this request then simply ignore this email and no changes will be apply
    '''
    mail.send(msg)


@app.route('/reset_password', methods=('GET', 'POST'))
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_email(user)
            flash(
                'An email has been sent with instruction to reset your password', 'info')
            return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)


@app.route('/reset_password/<token>', methods=('GET', 'POST'))
def reset_token(token):
    user = User.verify_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if request.method == "POST":
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(
                form.password.data).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been updated! you are now able to login.')
            return redirect('login')
    return render_template('reset_token.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
