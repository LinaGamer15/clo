from functools import wraps

from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask import Flask, render_template, url_for, redirect, jsonify, request, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import SubmitField, StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length, URL
import stripe

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dfkdskfdksaof8AFUWASIOTFJCZIOcx&F87EWSZU9RL'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///col.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

stripe_keys = {
    'secret_key': 'sk_test_51JS3a0KKmcttL5TyftYbsNTpO16ZJTBA7slVnximEHXdq5oFd5f26LsrwqqnIqBWDYU3jt6Fqj3hn95TPUSgJ7PL00HMlMq79B',
    'publishable_key': 'pk_test_51JS3a0KKmcttL5TySXiMnQY6zKz9zf9ywtJ6bCPTesoiQpPhAWRzhvvJ2sZJXe3rpa32dOmhD3P6kj7NGbdWDXAf003bO146HQ',
    'endpoint_secret': 'endpoint'}

stripe.api_key = stripe_keys['secret_key']


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            if current_user.id != 1:
                return abort(403)
        except AttributeError:
            return abort(401)
        return f(*args, **kwargs)

    return decorated_function


class COL(db.Model):
    __tablename__ = 'col'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    price = db.Column(db.String(250), nullable=False)
    image = db.Column(db.String(400), nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(250), nullable=False)
    last_name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    login = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)


class SignUp(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    login = StringField('Login', validators=[DataRequired(), Length(min=6)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    repeat_password = PasswordField('Repeat Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Sign Up')


class SignIn(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Sign In')


class Add(FlaskForm):
    name = StringField('Name Product', validators=[DataRequired()])
    price = StringField('Price', validators=[DataRequired()])
    image = StringField('Image URL', validators=[DataRequired(), URL()])
    submit = SubmitField('OK')


db.create_all()


@app.route('/')
def home():
    all_product = COL.query.all()
    return render_template('index.html', products=all_product, key=str(stripe_keys['publishable_key']),
                           current_user=current_user)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUp()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('You\'ve already signed up with that email, log in instead!')
            return redirect(url_for('signin'))
        elif form.password.data == form.repeat_password.data:
            hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            hashed_login = generate_password_hash(form.login.data, method='pbkdf2:sha256', salt_length=8)
            new_user = User(first_name=form.first_name.data, last_name=form.last_name.data, email=form.email.data,
                            login=hashed_login, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
        elif form.password.data != form.repeat_password.data:
            flash('Password was repeated incorrectly, please try again.')
    return render_template('signup.html', form=form, current_user=current_user)


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    form = SignIn()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('That email does not exist, please try again.')
        elif not check_password_hash(user.password, form.password.data):
            flash('Password incorrect, please try again.')
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template('signin.html', form=form, current_user=current_user)


@app.route('/add', methods=['GET', 'POST'])
@admin_only
def add():
    form = Add()
    if form.validate_on_submit():
        new_product = COL(name=form.name.data, price=form.price.data, image=form.image.data)
        db.session.add(new_product)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add.html', form=form, current_user=current_user, is_update=False)


@app.route('/update', methods=['GET', 'POST'])
@admin_only
def update():
    list_id = request.args.getlist('id')
    product = COL.query.filter_by(id=int(list_id[0])).first()
    form = Add(name=product.name, price=product.price, image=product.image)
    print(product.name)
    if form.validate_on_submit():
        product.name = form.name.data
        product.price = form.price.data
        product.image = form.image.data
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add.html', form=form, current_user=current_user, is_update=True, update_id=list_id[0])


@app.route('/buy')
def buy():
    id_ = request.args.getlist('id')
    product = COL.query.filter_by(id=int(id_[0])).first()
    domain_url = 'http://localhost:5000/'
    stripe.api_key = stripe_keys["secret_key"]
    try:
        checkout_session = stripe.checkout.Session.create(
            success_url=domain_url + 'success',
            cancel_url=domain_url + 'cancelled',
            payment_method_types=['card'],
            mode='payment',
            line_items=[{
                'name': product.name,
                'quantity': 1,
                'currency': 'usd',
                'amount': int(float(product.price) * 100),
                'images': [
                    product.image]
            }]
        )
        return jsonify({'sessionId': checkout_session['id']})
    except Exception as e:
        return jsonify(error=str(e)), 403


@app.route('/webhook')
def webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_keys['endpoint_secret']
        )
    except ValueError as s:
        return 'Invalid signarute', 400
    except stripe.error.SignatureVerificationError as e:
        return 'Invalid signarute', 400
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        handle_checkout_session(session)
        return 'Success', 200


def handle_checkout_session(session):
    print('Payment was successful.')


@app.route('/cancelled')
def cancelled():
    return render_template('cancelled.html', current_user=current_user)


@app.route('/success')
def success():
    return render_template('success.html', current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/delete')
@admin_only
def delete():
    id_ = request.args.getlist('id')
    product = COL.query.filter_by(id=int(id_[0])).first()
    db.session.delete(product)
    db.session.commit()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
