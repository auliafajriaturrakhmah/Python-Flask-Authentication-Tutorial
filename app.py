from flask import Flask, render_template, url_for, redirect, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import mysql.connector
import jwt 
import datetime 
from functools import wraps


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


mydb = mysql.connector.connect(
    host = 'localhost',
    port = 3308,
    user = 'root',
    password = '',
    database = 'infokost',
)
mydb_cursor = mydb.cursor()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


# decorator untuk kunci endpoint / authentikasi
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        # token akan diparsing melalui parameter di endpoint
        token = request.args.get('token')

        # cek token ada atau tidak
        if not token:
            return jsonify({'Alert!': 'Token is missing!'}), 401

        # decode token yang diterima 
        try:
            output = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
             return jsonify({'Message': 'Invalid token'}), 403
        return f(*args, **kwargs)
    return decorator


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                # hasilkan nomor token
                token = jwt.encode(
                    {
                        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
                    }, app.config['SECRET_KEY'], algorithm="HS256"
                )
                return ({
                    "token": token,
                })
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard():
    mydb_cursor.execute('SELECT nama_kost, alamat, kota FROM data_kost LIMIT 10')
    datas = mydb_cursor.fetchall()
    return jsonify(datas)


if __name__ == "__main__":
    app.run(debug=True)