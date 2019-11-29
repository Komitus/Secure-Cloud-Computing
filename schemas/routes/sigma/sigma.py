from schemas import db
from schemas.session import Session
from flask import request, current_app, jsonify
from schemas.protocols import SIGMA
from schemas.utils import generate_token, string_to_point_FQ, point_to_string_FQ
from pprint import pformat

PROTOCOL = "sigma"
routes = []
sigma_sk, sigma_pk = SIGMA.keygen()

def sigma_init():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        current_app.logger.info(f"[SIGMA] Received payload:\n{pformat(payload)}")
        X_str = payload.get("X")
        X = string_to_point_FQ(X_str)
        y, Y = SIGMA.gen_commit()
        current_app.logger.info(f"[SIGMA] Generated Y:\n{pformat(Y)}")
        sign_msg = X_str+point_to_string_FQ(Y)
        signature = SIGMA.sign_message(sigma_sk, sign_msg)
        current_app.logger.info(f"[SIGMA] Generated Signature:\n{pformat(signature)}")
        mac_key = SIGMA.gen_mac_key(X * y)
        mac = SIGMA.auth_message(mac_key, point_to_string_FQ(sigma_pk))
        current_app.logger.info(f"[SIGMA] Generated MAC:\n{pformat(mac)}")
        token = generate_token()
        db_data = {
            "X": X_str,
            "Y": point_to_string_FQ(Y),
            "y": y
        }
        try:
            db.session.add(Session(session_token=token, payload=db_data))
            db.session.commit()
        except:
            db.create_all()
            db.session.rollback()
            db.session.add(Session(session_token=token, payload=db_data))
            db.session.commit()
        response = {
            "session_token": token,
            "payload": {
                "b_mac": mac,
                "B": point_to_string_FQ(sigma_pk),
                "Y": point_to_string_FQ(Y),
                "sig": {
                    "A": point_to_string_FQ(signature[0]),
                    "s": str(signature[1]),
                    "msg": sign_msg
                }
            }
        }
        current_app.logger.info(f"[SIGMA] Sent response")
        return jsonify(response)

routes.append(dict(
    rule='/sigma/init',
    view_func=sigma_init,
    options=dict(methods=['POST'])))

def sigma_exchange():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL:
        token = data.get("session_token")
        payload = data.get("payload")
        current_app.logger.info(f"[SIGMA] Received payload:\n{pformat(payload)}")
        session = Session.query.filter_by(session_token=token).first()
        X = string_to_point_FQ(session.payload.get("X"))
        Y = string_to_point_FQ(session.payload.get("Y"))
        y = session.payload.get("y")
        try:
            db.session.delete(session)
            db.session.commit()
        except:
            db.create_all()
            db.session.rollback()
            db.session.delete(session)
            db.session.commit()
        pk_a = string_to_point_FQ(payload.get("A"))
        a_mac = payload.get("b_mac")
        sig_a = payload.get("sig")
        if sig_a.get("msg") is not None:
            sign_msg = sig_a.get("msg")
        else:
            sign_msg = point_to_string_FQ(X) + point_to_string_FQ(Y)
        sign_X = string_to_point_FQ(sig_a.get("A"))
        sign_s = int(sig_a.get("s"))
        if SIGMA.verify_signature(pk_a, sign_X, sign_s, sign_msg):
            current_app.logger.info(f"[SIGMA] Verified signature")
            mac_key = SIGMA.gen_mac_key(X * y)
            if(SIGMA.verify_mac(mac_key, point_to_string_FQ(pk_a), a_mac)):
                current_app.logger.info(f"[SIGMA] Verified MAC")
                msg = payload.get("msg")
                K = SIGMA.gen_session_key(X * y)
                enc_msg = SIGMA.encode_msg(msg, K)
                return jsonify({
                    "msg": enc_msg
                })

routes.append(dict(
    rule='/sigma/exchange',
    view_func=sigma_exchange,
    options=dict(methods=['POST'])))