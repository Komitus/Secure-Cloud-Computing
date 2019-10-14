from flask import Flask, escape, request, jsonify, g
from flasgger import Swagger, swag_from
import secrets
from sis import SIS
import sqlite3
from utils import string_to_point


DATABASE = 'base.db'

app = Flask(__name__)
swagger = Swagger(app)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            contents = f.read()
            db.cursor().executescript(contents)
        db.commit()

@app.route('/protocols/<protocol>/init', methods=["POST"])
@swag_from('/openapi/api.yaml')
def init(protocol):
    if protocol == "sis":
        data = request.json
        A = data.get("payload").get("A")
        X = data.get("payload").get("X")
        token = secrets.token_hex(16)
        c = SIS.gen_challenge() 
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("insert into sis values (?, ?, ? ,?)", (token, A, X, str(c)))
            db.commit()
        response = {"session_token": token, "payload":{"c": str(c)}}
        return jsonify(response)
        

    return None

@app.route('/protocols/<protocol>/verify', methods=["POST"])
@swag_from('/openapi/api.yaml')
def verify(protocol):
    if protocol == "sis":
        data = request.json
        s = int(data.get("payload").get("s"))
        token = data.get("session_token")
        with app.app_context():
            db = get_db()
            cur = db.cursor()
            cur.execute("select a, x, c from sis where session_token = ?", (token,))
            row = cur.fetchone()
            A = string_to_point(row[0])
            X = string_to_point(row[1])
            c = int(row[2])
            cur.execute('DELETE FROM sis WHERE session_token = ?', (token,))
            db.commit()
            answer = SIS.verify(A, X, c, s)
            if answer:
                return jsonify({"verified": answer}), 200
            else:
                return jsonify({"verified": answer}), 403
            
        return jsonify(answer)

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=8080)
