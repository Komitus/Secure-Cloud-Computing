from flask import Flask, escape, request, jsonify, g
from flasgger import Swagger, swag_from
import secrets
from sis import SIS
from ois import OIS
import sqlite3
from utils import string_to_point, generate_token, unpack


DATABASE = 'base.db'

app = Flask(__name__)
swagger = Swagger(app)

implemented_protocols = ["sis", "ois"]
init_list = ["sis", "ois"]
verify_list = ["sis", "ois"]

def schnorr_init(data):
    payload = data.get("payload")
    A = payload.get("A")
    X = payload.get("X")
    token = generate_token()
    c = SIS.gen_challenge()
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("insert into sis values (?, ?, ? ,?)", (token, A, X, str(c)))
        db.commit()
    response = {
        "session_token": token, 
        "payload": {
            "c": str(c)
        }
    }
    return jsonify(response)

def schnorr_verify(data):
    payload = data.get("payload")
    token = data.get("session_token")
    s = int(payload.get("s"))
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
            return jsonify({
                "verified": answer
            }), 200
        else:
            return jsonify({
                "verified": answer
            }), 403
        
    return jsonify(answer)

def okamoto_init(data):
    payload = data.get("payload")
    A = payload.get("A")
    X = payload.get("X")
    token = generate_token()
    c = OIS.gen_challenge()
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("insert into ois values (?, ?, ? ,?)", (token, A, X, str(c)))
        db.commit()
    response = {
        "session_token": token, 
        "payload": {
            "c": str(c)
        }
    }
    return jsonify(response)

def okamoto_verify(data):
    payload = data.get("payload")
    token = data.get("session_token")
    s_1 = int(payload.get("s1"))
    s_2 = int(payload.get("s2"))
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("select a, x, c from ois where session_token = ?", (token,))
        row = cur.fetchone()
        A = string_to_point(row[0])
        X = string_to_point(row[1])
        c = int(row[2])
        cur.execute('DELETE FROM ois WHERE session_token = ?', (token,))
        db.commit()
        answer = OIS.verify(A, X, c, (s_1, s_2))
        if answer:
            return jsonify({
                "verified": answer
            }), 200
        else:
            return jsonify({
                "verified": answer
            }), 403
        
    return jsonify(answer)

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

init_protocols = {
    "sis": schnorr_init,
    "ois": okamoto_init,
}

verify_protocols = {
    "sis": schnorr_verify,
    "ois": okamoto_verify,
}

@app.route('/protocols', methods=["GET"])
def protocol_list():
    return jsonify({
        "schemas": implemented_protocols
    })

@app.route(f'/protocols/<any({unpack(init_list)}):protocol>/init', methods=["POST"])
def init(protocol):
    data = request.json
    if protocol==data.get("protocol_name"):
        return init_protocols[protocol](data)

@app.route(f'/protocols/<any({unpack(verify_list)}):protocol>/verify', methods=["POST"])
def verify(protocol):
    data = request.json
    if protocol==data.get("protocol_name"):
        return verify_protocols[protocol](data)
    
        
if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=8080)
