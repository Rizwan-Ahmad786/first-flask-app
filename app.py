from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length, DataRequired, EqualTo, ValidationError
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager , login_manager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Hi_this_is_my_todo_task_app!'
ENV = 'prod'

if ENV == 'dev':
    app.debug=True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:rizwan786@localhost/db_postgres'
else:
    app.debug=True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://qjbgrgemhxpznn:4c2a1c3cd4933ab3fe29bb20fa6d06819f7fd69d8d2d312e00bb3d11e2736d69@ec2-34-193-112-164.compute-1.amazonaws.com:5432/d89v8ls5o6h015'
    
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    # __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(200), index=True, unique=True)
    email = db.Column(db.String(200), index=True, unique=True)
    password = db.Column(db.String(200))
    todos = db.relationship('Todo', backref='author', lazy='dynamic')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Todo(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    des = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class LoginForm(FlaskForm):
    username = StringField('User Name', validators=[InputRequired(), Length(min=4, max=35)])
    password = PasswordField('Password',validators=[InputRequired(), Length(min=8, max=80)] )
    remember = BooleanField('remember me')


class RegistrationForm(FlaskForm):
    username = StringField('User Name', validators=[InputRequired(), Length(min=4, max=35)])
    email = StringField('Email', validators=[InputRequired(),Email(message='Invalid email'), Length(max=35)])
    password = PasswordField('Password',validators=[InputRequired(), Length(min=8, max=80)] )
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])


    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different uniqe username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')


@app.route('/')
@app.route('/login', methods=['Get','POST'])
def login():
    form = LoginForm()
    if request.method == "POST":
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user is None or not check_password_hash(user.password, form.password.data): 
                flash('Invalid username or password')
                return redirect(url_for('login'))
            login_user(user, remember=form.remember.data)
            return redirect('index')
    else:
        return render_template('login.html', form=form)


@app.route('/signup', methods=['Get','POST'])
def signup():
    form = RegistrationForm()
    if request.method == "POST":
         if form.validate_on_submit():
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            newuser = User(username=form.username.data, email=form.email.data, password = hashed_password)
            db.session.add(newuser)
            db.session.commit()
            return redirect('login')
    return render_template('signup.html', form=form)


@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == "POST":
        title = request.form['title']
        des = request.form['des']
        newtodo = Todo(title=title, des=des, user_id=current_user.id)
        db.session.add(newtodo)
        db.session.commit()
    alldata = Todo.query.filter_by(user_id=current_user.id)
    return render_template('index.html', alldata=alldata)


@app.route('/add_todo')
def add_todo():
    return render_template('add_todo.html')


@app.route('/update/<int:id>', methods=['GET','POST'])
def update(id):
    if request.method=='POST':
        title = request.form['title']
        des = request.form['des']
        data = Todo.query.filter_by(id=id, user_id=current_user.id).first()
        data.title = title
        data.des = des
        db.session.add(data)
        db.session.commit()
        return redirect('/index')
    data = Todo.query.filter_by(id=id).first()
    return render_template('/update.html', data=data)


@app.route('/delete/<int:id>')
def delete(id):
    delete_todo = Todo.query.filter_by(id=id).first()
    db.session.delete(delete_todo)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__=='__main__':
    app.run(debug=True)