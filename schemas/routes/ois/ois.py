from schemas import db
from pprint import pformat
from schemas.session import Session
from flask import request, current_app, jsonify
from schemas.protocols import OIS
from schemas.utils import generate_token, string_to_point_FQ

PROTOCOL = "ois"
routes = []

def ois_init():
    data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        current_app.logger.info(f"[OIS] Received payload:\n{pformat(payload)}")
        A = payload.get("A")
        X = payload.get("X")
        token = generate_token()
        c = OIS.gen_challenge()
        current_app.logger.info(f"[OIS] Generated c:\n{pformat(c)}")
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
        current_app.logger.info(f"[OIS] Sent response")
        return jsonify(response)

routes.append(dict(
    rule='/ois/init',
    view_func=ois_init,
    options=dict(methods=['POST'])))

def ois_verify():
    data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        token = data.get("session_token")
        s_1 = int(payload.get("s1"))
        s_2 = int(payload.get("s2"))
        current_app.logger.info(f"[OIS] Received s_1:\n{pformat(s_1)}\ns_2:\n{pformat(s_2)}")
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
        answer = OIS.verify(A, X, c, (s_1, s_2))
        current_app.logger.info(f"[OIS] Verification: {pformat(answer)}")
        if answer:
            return jsonify({
                "verified": answer
            }), 200
        else:
            return jsonify({
                "verified": answer
            }), 403

routes.append(dict(
    rule='/ois/verify',
    view_func=ois_verify,
    options=dict(methods=['POST'])))