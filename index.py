import secrets
import sqlite3

from flask import Flask, escape, g, jsonify, request

from blsss import BLSSS
from gjss import GJSS
from msis import MSIS
from ois import OIS
from sis import SIS
from sss import SSS
from naxos import NAXOS
from utils import (generate_token, string_to_point_FQ, string_to_point_FQ2, point_to_string_FQ,
                   unpack)

DATABASE = 'base.db'

app = Flask(__name__)
# TODO: Refactor database calls -- Use SQLALCHEMY
# TODO: Refactor routes

implemented_protocols = ["sis", "ois", "sss", "msis", "blsss", "gjss"]
init_list = ["sis", "ois", "msis"]
verify_list = ["sis", "ois", "sss", "msis", "blsss", "gjss"]
pkey_list = ["naxos"]
exchange_list = ["naxos"]

naxos_sk, naxos_pk = NAXOS.keygen()

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
        A = string_to_point_FQ(row[0])
        X = string_to_point_FQ(row[1])
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
        A = string_to_point_FQ(row[0])
        X = string_to_point_FQ(row[1])
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
        
def schnorr_signature_verify(data):
    payload = data.get("payload")
    msg = payload.get("msg")
    A = string_to_point_FQ(payload.get("A"))
    X = string_to_point_FQ(payload.get("X"))
    s = int(payload.get("s"))
    c = SSS.gen_challenge(msg, X)
    answer = SSS.verify(A, X, c, s)
    return jsonify({
        "valid": answer
    })
            
def mod_schnorr_init(data):
    payload = data.get("payload")
    A = payload.get("A")
    X = payload.get("X")
    token = generate_token()
    c = MSIS.gen_challenge()
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("insert into msis values (?, ?, ? ,?)", (token, A, X, str(c)))
        db.commit()
    response = {
        "session_token": token, 
        "payload": {
            "c": str(c)
        }
    }
    return jsonify(response)

def mod_schnorr_verify(data):
    payload = data.get("payload")
    token = data.get("session_token")
    S = string_to_point_FQ2(payload.get("S"))
    with app.app_context():
        db = get_db()
        cur = db.cursor()
        cur.execute("select a, x, c from msis where session_token = ?", (token,))
        row = cur.fetchone()
        A = string_to_point_FQ(row[0])
        X = string_to_point_FQ(row[1])
        c = int(row[2])
        g_hat = MSIS.gen_g2_generator(X, c)
        cur.execute('DELETE FROM msis WHERE session_token = ?', (token,))
        db.commit()
        answer = MSIS.verify(A, X, c, g_hat, S)
        if answer:
            return jsonify({
                "verified": answer
            }), 200
        else:
            return jsonify({
                "verified": answer
            }), 403

def bls_signature_verify(data):
    payload = data.get("payload")
    msg = payload.get("msg")
    A = string_to_point_FQ(payload.get("A"))
    sigma = string_to_point_FQ2(payload.get("sigma"))
    h = BLSSS.gen_g2_generator(msg)
    answer = BLSSS.verify(sigma, A, h)
    return jsonify({
        "valid": answer
    })

def gj_signature_verify(data):
    payload = data.get("payload")
    msg = payload.get("msg")
    A = string_to_point_FQ(payload.get("A"))
    sigma = payload.get("sigma")
    s = int(sigma.get("s"))
    c = int(sigma.get("c"))
    r = int(sigma.get("r"))
    z = string_to_point_FQ2(sigma.get("z"))
    h = GJSS.gen_h(msg, r)
    u, v = GJSS.calc_commits(s, c, z, h, A)
    c_prim = GJSS.gen_challenge(h, A, z, u, v)
    answer = GJSS.verify(c, c_prim)
    return jsonify({
        "valid": answer
    })

def naxos_pkey():
    return jsonify({
        "B": point_to_string_FQ(naxos_pk)
    })

def naxos_exchange(data):
    payload = data.get("payload")
    X = string_to_point_FQ(payload.get("X"))
    A = string_to_point_FQ(payload.get("A"))
    msg = payload.get("msg")
    ephemeral = NAXOS.gen_ephemeral(128)
    Y = NAXOS.calc_commit(ephemeral, naxos_sk)
    K = NAXOS.calc_keyB(A, ephemeral, naxos_sk, X, naxos_pk)
    enc_msg = NAXOS.encode_msg(msg, K)
    return jsonify({
        "Y" : point_to_string_FQ(Y),
        "msg": enc_msg
    })

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
    "msis": mod_schnorr_init,
}

verify_protocols = {
    "sis": schnorr_verify,
    "ois": okamoto_verify,
    "sss": schnorr_signature_verify,
    "msis": mod_schnorr_verify,
    "blsss": bls_signature_verify,
    "gjss": gj_signature_verify
}

pkey_protocols = {
    "naxos": naxos_pkey,
}

exchange_protocols = {
    "naxos": naxos_exchange,
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
    
@app.route(f'/protocols/<any({unpack(pkey_list)}):protocol>/pkey', methods=["GET"])
def pkey(protocol):
    return pkey_protocols[protocol]()
          
@app.route(f'/protocols/<any({unpack(exchange_list)}):protocol>/exchange', methods=["POST"])
def exchange(protocol):
    data = request.json
    if protocol==data.get("protocol_name"):
        return exchange_protocols[protocol](data)

if __name__ == '__main__':
    init_db()
    app.run(host="0.0.0.0", port=8080)
