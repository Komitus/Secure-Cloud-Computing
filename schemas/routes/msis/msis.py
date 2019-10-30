from schemas import db
from schemas.session import Session
from flask import request, current_app, jsonify
from schemas.protocols import MSIS
from schemas.utils import generate_token, string_to_point_FQ, string_to_point_FQ2
from pprint import pformat

PROTOCOL = "msis"
routes = []

def msis_init():
    data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        current_app.logger.info(f"[MSIS] Received payload:\n{pformat(payload)}")
        A = payload.get("A")
        X = payload.get("X")
        token = generate_token()
        c = MSIS.gen_challenge()
        current_app.logger.info(f"[MSIS] Generated c:\n{pformat(c)}")
        db_data = {
            "A": A,
            "X": X,
            "c": c        
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
                "c": str(c)
            }
        }
        current_app.logger.info(f"[MSIS] Sent response")
        return jsonify(response)

routes.append(dict(
    rule='/msis/init',
    view_func=msis_init,
    options=dict(methods=['POST'])))

def msis_verify():
    data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        token = data.get("session_token")
        S = string_to_point_FQ2(payload.get("S"))
        current_app.logger.info(f"[MSIS] Received S:\n{pformat(S)}")
        session = Session.query.filter_by(session_token=token).first()
        A = string_to_point_FQ(session.payload.get("A"))
        X = string_to_point_FQ(session.payload.get("X"))
        c = session.payload.get("c")
        g_hat = MSIS.gen_g2_generator(X, c)
        try:
            db.session.delete(session)
            db.session.commit()
        except:
            db.create_all()
            db.session.rollback()
            db.session.delete(session)
            db.session.commit()
        answer = MSIS.verify(A, X, c, g_hat, S)
        current_app.logger.info(f"[MSIS] Verification: {pformat(answer)}")
        if answer:
            return jsonify({
                "verified": answer
            }), 200
        else:
            return jsonify({
                "verified": answer
            }), 403

routes.append(dict(
    rule='/msis/verify',
    view_func=msis_verify,
    options=dict(methods=['POST'])))