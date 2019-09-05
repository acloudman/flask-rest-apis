from datetime import timedelta

from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_restful import Api

from resources.item import Item, ItemList
from resources.user import UserRegister, User, UserLogin, TokenRefresh, UserLogout
# from security import authenticate, identity
from resources.store import Store, StoreList 
from blacklist import BLACKLIST

app = Flask(__name__)
# app.config['JWT_AUTH_URL_RULE'] = '/login'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=1800)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(hours=24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_BLACKLIST_ENABLED']= True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config['PROPAGATE_EXCEPTIONS'] = True
app.secret_key = 'avi'  #app.config['JWT_SECRET_KEY']
api = Api(app)


jwt = JWTManager(app)

@jwt.user_claims_loader
def add_claims_to_jwt(identity):
    if identity == 1:
        return {'is_admin': True}
    else:
        return {'is_admin': False}

@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return decrypted_token['jti'] in BLACKLIST

@jwt.expired_token_loader
def  expired_token_callback():
    return jsonify({
        'description': 'The token has expired',
        'error': 'token expired'
    }), 401

@jwt.invalid_token_loader
def  invalid_token_callback():
    return jsonify({
        'description': 'Signature varification failed.',
        'error': 'invalid token'
    }), 401

@jwt.unauthorized_loader
def  missing_token_callback():
    return jsonify({
        'description': 'Request does not contain an access token.',
        'error': 'authorizatiom required'
    }), 401

@jwt.needs_fresh_token_loader
def  token_not_fresh_callback():
    return jsonify({
        'description': 'The token is not fresh',
        'error': 'fresh token required'
    }), 401

@jwt.revoked_token_loader
def  revoke_token_callback():
    return jsonify({
        'description': 'The token has been revoked',
        'error': 'token revoked'
    }), 401

api.add_resource(Store, '/store/<string:name>')
api.add_resource(Item, '/item/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(StoreList, '/stores')
api.add_resource(UserRegister, '/register')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserLogin, '/login')
api.add_resource(UserLogout, '/logout')
api.add_resource(TokenRefresh, '/refresh')






if __name__ == "__main__":
    from db import db
    db.init_app(app)
    app.run(port=5000, debug=True)
