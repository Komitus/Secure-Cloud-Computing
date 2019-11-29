import click
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask.cli import with_appcontext
from flask import request
import os
import logging
import json
from schemas.cryptoboxs import Salsa, Chacha
from schemas.utils import read_key, base64_encode, base64_decode

db = SQLAlchemy()

def configure_logging():
    FORMAT = '%(message)s'
    logging.basicConfig(level=logging.DEBUG, format=FORMAT)
    logging.getLogger('werkzeug').setLevel(logging.DEBUG)

def create_app(test_config=None):    
    app = Flask(__name__, instance_relative_config=True)
    db_url = os.environ.get("DATABASE_URL")

    if db_url is None:
        # default to a sqlite database in the instance folder
        db_url = f'sqlite:///{os.path.join(app.instance_path, "base.db")}'
        # ensure the instance folder exists
        os.makedirs(app.instance_path, exist_ok=True)

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev"),
        SQLALCHEMY_DATABASE_URI=db_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )    

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.update(test_config)

    db.init_app(app)
    with app.app_context():
        init_db()
    app.cli.add_command(init_db_command)
    configure_logging() 

    from schemas.routes import bp 
    salsa_key = read_key("salsa_key.bin")
    salsabox = Salsa(salsa_key)
    chacha_key = read_key("chacha_key.bin")
    chachabox = Chacha(chacha_key)
    @app.before_request
    def before():
        if "salsa" in request.base_url:
            if request.data:
                d = request.json
                ciphertext = d.get("ciphertext")
                nonce =  d.get("nonce")
                req_cipher = base64_decode(ciphertext)
                req_nonce = base64_decode(nonce)
                enc_json = salsabox.decrypt(req_cipher, req_nonce)
                data = json.loads(enc_json.decode())
                request.data = data
        elif "chacha" in request.base_url:
            if request.data:
                d = request.json
                ciphertext = d.get("ciphertext")
                tag = d.get("tag")
                nonce =  d.get("nonce")
                req_cipher = base64_decode(ciphertext)
                req_nonce = base64_decode(nonce)
                req_tag = base64_decode(tag)
                enc_json = chachabox.decrypt(req_cipher, req_tag ,req_nonce)
                data = json.loads(enc_json.decode())
                request.data = data
                
    @app.after_request
    def after(response):
        if "salsa" in request.base_url:
            cipher, nonce = salsabox.encrypt(response.get_data())
            salsa_json = {
                "ciphertext": base64_encode(cipher).decode("utf-8"),
                "nonce": base64_encode(nonce).decode("utf-8"),
            }
            response.set_data(json.dumps(salsa_json))
            app.logger.info(f'Response: {response.get_data()}')
        elif "chacha" in request.base_url:
            cipher, tag, nonce = chachabox.encrypt(response.get_data())
            chacha_json = {
                "ciphertext": base64_encode(cipher).decode("utf-8"),
                "tag": base64_encode(tag).decode("utf-8"),
                "nonce": base64_encode(nonce).decode("utf-8"),
            }
            response.set_data(json.dumps(chacha_json))
            app.logger.info(f'Response: {response.get_data()}')
        return response
        

    app.register_blueprint(bp, url_prefix='/protocols')
    app.register_blueprint(bp, url_prefix='/salsa/protocols')
    app.register_blueprint(bp, url_prefix='/chacha/protocols')

    return app


def init_db():
    db.drop_all()
    db.create_all()

@click.command("init-db")
@with_appcontext
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
