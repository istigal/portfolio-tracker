from functools import wraps
import jwt
import requests
from flask import Flask, request, render_template, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import datetime
import uuid
from werkzeug.security import check_password_hash, generate_password_hash
import os


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get('SECRET_KEY')
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///portfolio.db"
db = SQLAlchemy()
db.init_app(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    public_id = db.Column(db.String(100))
    password = db.Column(db.String(250), nullable=False)
    admin = db.Column(db.Boolean)
    registered = db.Column(db.DateTime, default=datetime.datetime.utcnow())


class Portfolio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.String(100))
    value = db.Column(db.Float)
    public_id = db.Column(db.String(100))
    created = db.Column(db.DateTime, default=datetime.datetime.utcnow())


class Position(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(20))
    name = db.Column(db.String(100))
    coin_id = db.Column(db.String(100))
    quantity = db.Column(db.Float)
    buy_price = db.Column(db.Float)
    current_price = db.Column(db.Float)
    value = db.Column(db.Float)
    price_change = db.Column(db.Integer)
    added = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    portfolio_id = db.Column(db.String(100))


gecko = 'https://api.coingecko.com/api/v3/'
api_key = os.environ.get('CG_API')
all_coins = requests.get(f"{gecko}/coins/list?include_platform=true&x_cg_api_key={api_key}").json()


def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization").split()[1]
        if not token:
            return jsonify({"message": "Token is missing"})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"], options={"verify_exp": False})
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"message": "Token is invalid!"}), 401
        return f(current_user, *args, **kwargs)
    return wrapper


@app.route('/register', methods=["POST"])
def register():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    if not email or not name or not password:
        return jsonify({'message': 'Please introduce a valid email, name and password.'})
    exists = User.query.filter_by(email=email).first()
    if exists:
        return jsonify({'message': 'This email address is already registered'})
    new_user = User(public_id=str(uuid.uuid4()),
                    email=email,
                    name=name,
                    password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=16),
                    admin=False)
    db.create_all()
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Successfully registered'})


@app.route('/users')
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})
    users = User.query.all()
    all_users = []
    for user in users:
        user_data = {
            'public_id': user.public_id,
            'email': user.email,
            'name': user.name,
            'password': user.password,
            'admin': user.admin,
            'registered': user.registered
        }
        all_users.append(user_data)
    return all_users


@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify 1', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    user = User.query.filter_by(email=auth.username).first()
    if not user:
        return make_response('Could not verify 2', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    if not check_password_hash(user.password, auth.password):
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})
    token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)},
                       app.config['SECRET_KEY'])
    return jsonify({'token': token})


@app.route('/user/<public_id>')
@token_required
def get_user_data(current_user, public_id):
    if current_user.public_id != public_id and not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})
    user = User.query.filter_by(public_id=public_id).first()
    user_data = {
        'public_id': user.public_id,
        'email': user.email,
        'name': user.name,
        'password': user.password,
        'admin': user.admin,
        'registered': user.registered
    }
    return jsonify(user_data)


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})
    user.admin = True
    db.session.commit()
    return jsonify({'message': 'The user was promoted'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if current_user.public_id != public_id and not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})
    user = User.query.filter_by(public_id=public_id).first()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'The user was deleted'})


@app.route('/dashboard')
@token_required
def dashboard(current_user):
    pf_data = Portfolio.query.filter_by(user_id=current_user.public_id).all()
    all_portfolio = [{'name': p.name, 'value': p.value, 'id': p.public_id, 'created': p.created} for p in pf_data]
    return all_portfolio


@app.route('/dashboard', methods=['POST'])
@token_required
def create_portfolio(current_user):
    name = request.form.get('name')
    if not name:
        return jsonify({'message': 'Please introduce a valid name.'})
    new_portfolio = Portfolio(name=name,
                              user_id=current_user.public_id,
                              value=0,
                              public_id=str(uuid.uuid4()))
    db.session.add(new_portfolio)
    db.session.commit()
    return jsonify({'message': f"The portfolio named '{new_portfolio.name}' was successfully created."})


@app.route("/dashboard/<portfolio_id>")
@token_required
def get_portfolio(current_user, portfolio_id):
    portfolio = Portfolio.query.filter_by(public_id=portfolio_id).first()
    if current_user.public_id != portfolio.user_id and not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})

    if not portfolio:
        return jsonify({'message': 'Portfolio not found.'})
    pf_data = {
        'name': portfolio.name,
        'value': portfolio.value,
        'created': portfolio.created
    }
    return jsonify(pf_data)


@app.route('/dashboard/<portfolio_id>', methods=['PUT'])
@token_required
def change_name(current_user, portfolio_id):
    portfolio = Portfolio.query.filter_by(public_id=portfolio_id).first()
    if current_user.public_id != portfolio.user_id and not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})
    if not portfolio:
        return jsonify({'message': 'Portfolio not found.'})
    name = request.form.get('name')
    if not name:
        return jsonify({'message': 'No change made.'})
    portfolio.name = name
    db.session.commit()
    return jsonify({'message': 'Portfolio name successfully changed.'})


@app.route('/dashboard/<portfolio_id>', methods=["DELETE"])
@token_required
def delete_portfolio(current_user, portfolio_id):
    portfolio = Portfolio.query.filter_by(public_id=portfolio_id).first()
    if current_user.public_id != portfolio.user_id and not current_user.admin:
        return jsonify({'message': 'Cannot perform that function'})
    if not portfolio:
        return jsonify({'message': 'Portfolio not found.'})
    db.session.delete(portfolio)
    db.session.commit()
    return jsonify({'message': f"The portfolio named '{portfolio.name}' has been deleted."})


@app.route('/search')
@token_required
def get_coins(current_user):
    coin_name = request.args.get('coin').lower()
    coin_list = []
    for coin in all_coins:
        if coin_name in coin['name'].lower() or coin_name in coin['symbol'] or coin_name in coin['id']:
            coin_list.append(coin)
    return coin_list


@app.route('/<portfolio_id>', methods=['POST'])
@token_required
def add_position(current_user, portfolio_id):
    coin_id = request.form.get('coin_id')
    coin = [c for c in all_coins if c['id'] == coin_id]
    if not coin:
        return jsonify({'message': 'Bad request'})
    res = requests.get(f"{gecko}/simple/price?ids={coin_id}&vs_currencies=usd&x_cg_api_key={api_key}").json()
    price = res[coin_id]['usd']
    quantity = float(request.form.get('quantity'))
    try:
        buy_price = float(request.form.get('price'))
    except TypeError:
        buy_price = price
    if not quantity:
        return jsonify({'message': 'Introduce the quantity'})
    old_position = Position.query.filter_by(coin_id=coin_id).first()
    if not old_position:
        position = Position(name=coin[0]['name'],
                            coin_id=coin_id,
                            symbol=coin[0]['symbol'].upper(),
                            quantity=quantity,
                            buy_price=buy_price,
                            current_price=price,
                            value=quantity * price,
                            price_change=int((100 - price * 100 / buy_price) * -1),
                            portfolio_id=portfolio_id
                            )
        db.create_all()
        db.session.add(position)
        db.session.commit()
        return jsonify({'message': 'New position added'})
    new_buy_price = (old_position.buy_price * old_position.quantity + buy_price * quantity) / (old_position.quantity + quantity)
    old_position.quantity = quantity + old_position.quantity
    old_position.current_price = price
    old_position.buy_price = new_buy_price
    old_position.value = old_position.quantity * price
    old_position.price_change = int((100 - price * 100 / new_buy_price) * -1)
    db.session.commit()
    return jsonify({'message': 'Position modified'})


@app.route('/<portfolio_id>')
@token_required
def get_positions(current_user, portfolio_id):
    positions = Position.query.filter_by(portfolio_id=portfolio_id).all()
    elements = []
    for pos in positions:
        position = {
            'symbol': pos.symbol,
            'name': pos.name,
            'current_price': pos.current_price,
            'quantity': pos.quantity,
            'buy_price': pos.buy_price,
            'value': pos.value,
            'price_change': f'{pos.price_change} %'
        }
        elements.append(position)
    return elements


@app.route('/<portfolio_id>/<coin_id>', methods=['PUT'])
@token_required
def edit_position(current_user, portfolio_id, coin_id):
    res = requests.get(f"{gecko}/simple/price?ids={coin_id}&vs_currencies=usd&x_cg_api_key={api_key}").json()
    price = res[coin_id]['usd']
    position = Position.query.filter_by(coin_id=coin_id, portfolio_id=portfolio_id).first()
    position.quantity = float(request.form.get('quantity'))
    position.current_price = price
    position.buy_price = float(request.form.get('price'))
    position.value = position.quantity * price
    position.price_change = int((100 - price * 100 / position.buy_price) * -1)
    db.session.commit()
    return jsonify({'message': 'Position modified'})


@app.route('/<portfolio_id>/<coin_id>', methods=['DELETE'])
@token_required
def delete_position(current_user, portfolio_id, coin_id):
    position = Position.query.filter_by(coin_id=coin_id, portfolio_id=portfolio_id).first()
    db.session.delete(position)
    db.session.commit()
    return jsonify({'message': 'The position has been deleted'})


if __name__ == "__main__":
    app.run(debug=True)
