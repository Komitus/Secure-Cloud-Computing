from schemas import db
from schemas.session import Session
from flask import request, current_app, jsonify
from schemas.protocols.protocol_one_of_two import OneOf2Cloud
from schemas.encoding_utils import *
from schemas.protocols.protocols_utils import gen_example_messages
from pprint import pformat

PROTOCOL = "one_of_two"
routes = []

_NUM_OF_MESSAGES = 10
_MESSAGES = gen_example_messages(_NUM_OF_MESSAGES)


def one_of_two_send_A():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        current_app.logger.info(
            f"[one_of_two] Received payload:\n{pformat(payload)}")
        a, big_a = OneOf2Cloud.keygen()
        token = generate_token()
        db_data = {
            "a": mcl_to_str(a),
            "A": mcl_to_str(big_a)
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
                "A": mcl_to_str(big_a)
            }
        }
        current_app.logger.info(f"[one_of_two] Sent response A : {big_a}")
        return jsonify(response)


routes.append(dict(
    rule='/one_of_two/get_A',
    view_func=one_of_two_send_A,
    options=dict(methods=['POST'])))


def one_of_two_send_ciphertexts():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        big_b = mcl_from_str(payload.get("B"), mcl.G1)
        token = data.get("session_token")
        current_app.logger.info(f"[one_of_two] Received B:\n{pformat(big_b)}")
        session = Session.query.filter_by(session_token=token).first()
        a = mcl_from_str(session.payload.get("a"), mcl.Fr)
        big_a = mcl_from_str(session.payload.get("A"), mcl.G1)
        messages = _MESSAGES
        ciphertexts = OneOf2Cloud.gen_ciphertexts(a, big_a, messages, big_b)

        response = {
            "payload": {
                "ciphertexts": [cip.hex() for cip in ciphertexts]
            }
        }

        try:
            db.session.delete(session)
            db.session.commit()
        except:
            db.create_all()
            db.session.rollback()
            db.session.delete(session)
            db.session.commit()

        return jsonify(response)


routes.append(dict(
    rule='/one_of_two/get_ciphertexts',
    view_func=one_of_two_send_ciphertexts,
    options=dict(methods=['POST'])))
