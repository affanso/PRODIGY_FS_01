from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, validators
import re
import os


# Custom validator for password
def validate_password(form, field):
    password = field.data
    if not re.search(r'[A-Z]', password) or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password) or not re.search(r'[0-9]', password):
        raise validators.ValidationError('Password must have at least one capital letter and one special character and one number.')

class RegistrationFrom(FlaskForm):
    username = StringField(label='Username',validators=[validators.DataRequired()])
    email = EmailField(label='Email address',validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField(label='Password',validators=[validators.DataRequired(), validators.Length(min=8, message="Password must be at least 8 characters long."), validate_password])
    confirm = PasswordField(label='Confirm password', validators=[validators.DataRequired(), validators.EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

class LoginFrom(FlaskForm):
    email = EmailField(label='Email address',validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField(label='Password',validators=[validators.DataRequired()])
    submit = SubmitField('Sign In')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')

class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///users.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class User(UserMixin,db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(200), nullable=False)

with app.app_context():
    db.create_all()


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)



@app.route('/',methods=['POST','GET'])
def login():
    form = LoginFrom()
    if request.method == 'POST':
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            user = db.session.execute(db.select(User).where(User.email == email)).scalar()
            if not user:
                flash("That email does not exist, please try again.")
                return redirect(url_for('login'))
            elif not check_password_hash(user.password, password):
                flash('Password incorrect, please try again.')
                return redirect(url_for('login'))
            else:
                login_user(user)
                return redirect(url_for('success'))
        else:
            return render_template("login.html",form=form, logged_in=current_user.is_authenticated)
    else:
        return render_template("login.html",form=form, logged_in=current_user.is_authenticated)


@app.route('/registration',methods=['POST','GET'])
def registration():
    form = RegistrationFrom()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            email = form.email.data
            user = db.session.execute(db.select(User).where(User.email == email)).scalar()
            if user:
                flash("You've already signed up with that email, log in instead!")
                return redirect(url_for('login'))

            password = generate_password_hash(
                password=form.password.data,
                method='pbkdf2:sha256',
                salt_length=10
            )
            new_user = User(
                username= username,
                email= email,
                password= password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('success'))
        else:
            return render_template("registration.html",form=form, logged_in=current_user.is_authenticated)
    else:
        return render_template("registration.html",form=form, logged_in=current_user.is_authenticated)


@app.route('/success')
@login_required
def success():
    print(current_user.username)
    return render_template("success.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, port=port)