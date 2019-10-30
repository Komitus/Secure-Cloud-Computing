from schemas import db
from schemas.session import Session
from flask import request, current_app, jsonify
from schemas.protocols import SIS
from schemas.utils import generate_token, string_to_point_FQ
from pprint import pformat

PROTOCOL = "sis"
routes = []

def sis_init():
    data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        current_app.logger.info(f"[SIS] Received payload:\n{pformat(payload)}")
        A = payload.get("A")
        X = payload.get("X")
        token = generate_token()
        c = SIS.gen_challenge()
        current_app.logger.info(f"[SIS] Generated c:\n{pformat(c)}")
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
        current_app.logger.info(f"[SIS] Sent response")
        return jsonify(response)

routes.append(dict(
    rule='/sis/init',
    view_func=sis_init,
    options=dict(methods=['POST'])))

def sis_verify():
    data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        token = data.get("session_token")
        s = int(payload.get("s"))
        current_app.logger.info(f"[SIS] Received s:\n{pformat(s)}")
        session = Session.query.filter_by(session_token=token).first()
        A = string_to_point_FQ(session.payload.get("A"))
        X = string_to_point_FQ(session.payload.get("X"))
        c = session.payload.get("c")
        try:
            db.session.delete(session)
            db.session.commit()
        except:
            db.create_all()
            db.session.rollback()
            db.session.delete(session)
            db.session.commit()
        answer = SIS.verify(A, X, c, s)
        current_app.logger.info(f"[SIS] Verification: {pformat(answer)}")
        if answer:
            return jsonify({
                "verified": answer
            }), 200
        else:
            return jsonify({
                "verified": answer
            }), 403

routes.append(dict(
    rule='/sis/verify',
    view_func=sis_verify,
    options=dict(methods=['POST'])))