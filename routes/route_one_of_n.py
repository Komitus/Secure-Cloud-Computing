from flask import request, current_app, jsonify
from db_model import db
from db_model import Session, Keys
from protocols import OneOfNCloud, OneOf2Cloud
from routes.encoding_utils import *
from pprint import pformat

routes = []

_NUM_OF_MESSAGES = 10
_MESSAGES = gen_example_messages(_NUM_OF_MESSAGES)


def one_of_n_send_ciphertexts():
    PROTOCOL = "one_of_n"
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        current_app.logger.info(
            f"[one_of_n] Received payload:\n{pformat(payload)}")
        token = generate_token()
        messages = _MESSAGES
        cloud = OneOfNCloud(messages)
        key_pairs = [(key0.hex(), key1.hex())
                     for key0, key1 in cloud.key_pairs]

        ciphertexts = [cipher.hex() for cipher in cloud.gen_ciphertexts()]
        assert cloud.num_of_messages == len(ciphertexts)

        to_insert = [Keys(session_token=token, key_idx=i, key0_val=_key0, key1_val=_key1)
                     for i, (_key0, _key1) in enumerate(key_pairs)]

        try:
            db.session.add_all(to_insert)
            db.session.commit()
        except:
            db.create_all()
            db.session.rollback()
            db.session.add_all(to_insert)
            db.session.commit()

        response = {
            "session_token": token,
            "payload": {
                "ciphertexts": ciphertexts,
            },
        }

        return jsonify(response)


routes.append(dict(
    rule='/one_of_n/get_ciphertexts',
    view_func=one_of_n_send_ciphertexts,
    options=dict(methods=['POST'])))


##########################
# part with one of two
##########################


def one_of_n_send_A():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == "one_of_n":
        payload = data.get("payload")
        current_app.logger.info(
            f"[one_of_n] Received payload:\n{pformat(payload)}")
        token = data.get("session_token")
        a, big_a = OneOf2Cloud.keygen()
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
            current_app.logger.info(f"Bad session_token {token=}")
        response = {
            "payload": {
                "A": mcl_to_str(big_a)
            }
        }
        current_app.logger.info(f"[one_of_n] Sent response A : {big_a}")
        return jsonify(response)


routes.append(dict(
    rule='/one_of_n/get_A',
    view_func=one_of_n_send_A,
    options=dict(methods=['POST'])))


def one_of_n_send_two_ciphertexts():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == "one_of_n":
        payload = data.get("payload")
        big_b = mcl_from_str(payload.get("B"), mcl.G1)
        token = data.get("session_token")
        key_idx = data.get("payload").get("key_idx")
        current_app.logger.info(f"[one_of_n] Received B:\n{pformat(big_b)}")
        session_from_db = Session.query.filter_by(session_token=token).first()
        if session_from_db == None:
            return jsonify({})
        key_from_db = Keys.query.filter_by(
            session_token=token, key_idx=key_idx).first()
        a = mcl_from_str(session_from_db.payload.get("a"), mcl.Fr)
        big_a = mcl_from_str(session_from_db.payload.get("A"), mcl.G1)

        messages = [bytes.fromhex(key_from_db.key0_val),
                    bytes.fromhex(key_from_db.key1_val)]

        ciphertexts = OneOf2Cloud.gen_ciphertexts(a, big_a, messages, big_b)

        response = {
            "payload": {
                "ciphertexts": [cip.hex() for cip in ciphertexts]
            }
        }
        try:
            db.session.delete(session_from_db)
            db.session.delete(key_from_db)
            db.session.commit()
        except:
            db.create_all()
            db.session.rollback()
            db.session.delete(session_from_db)
            db.session.delete(key_from_db)
            db.session.commit()
        return jsonify(response)


routes.append(dict(
    rule='/one_of_n/get_two_ciphertexts',
    view_func=one_of_n_send_two_ciphertexts,
    options=dict(methods=['POST'])))
