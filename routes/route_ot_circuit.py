from db_model import Session, db
from flask import request, current_app, jsonify, abort
from protocols import OneOf2Cloud, CircuitCloud
from routes.encoding_utils import *
from .encoding_utils import gen_example_messages
from pprint import pformat
from globals import *
from mcl import *

PROTOCOL_NAME = Protocols.OT_CIRCUIT.value
PROTOCOL_ACTIONS = PROTOCOL_SPECS[PROTOCOL_NAME]["actions"]
routes = []
SECRET_CIRCUIT = [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1]


def ot_circuit_init():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL_NAME:
        payload = data.get("payload")
        current_app.logger.info(
            f"[{PROTOCOL_NAME}] Received payload:\n{pformat(payload)}")

        num_of_key_pairs = CircuitCloud.get_number_of_possible_inputs(
            SECRET_CIRCUIT)
        ephemerals = [OneOf2Cloud.keygen() for _ in range(num_of_key_pairs)]
        ot_ephemerals = [(mcl_to_str(seph), mcl_to_str(peph))
                         for seph, peph in ephemerals]

        token = generate_token()
        db_data = {
            'ot_ephemerals': ot_ephemerals,
        }

        try:
            db.session.add(Session(session_token=token, payload=db_data))
            db.session.commit()
        except:
            db.create_all()
            db.session.rollback()
            current_app.logger.info(f"Error at writing to db for {token=}")

        response = {
            "session_token": token,
            "payload": {
                'circuit_len': num_of_key_pairs,
                'pub_ephemerals': [
                    mcl_peph for _, mcl_peph in ot_ephemerals
                ]
            }
        }
        current_app.logger.info(
            f"[{PROTOCOL_NAME}] Sent response {response=}")
        return jsonify(response)


def ot_circuit_send_values():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL_NAME:
        payload = data.get("payload")
        token = data.get("session_token")
        session_data = Session.query.filter_by(session_token=token).first()
        session_payload = session_data.payload
        current_app.logger.info(
            f"[{PROTOCOL_NAME}] Received payload:\n{pformat(payload)}")

        client_ephemerals = payload.get('ephemerals')
        encoded, proper_keys = CircuitCloud.get_encoded_and_keys(
            SECRET_CIRCUIT)

        ciphertexts = []
        cloud_ephemerals = session_payload['ot_ephemerals']
        for idx, client_eph in enumerate(client_ephemerals):
            seph, peph = cloud_ephemerals[idx]

            pair_ciphertexts = OneOf2Cloud.gen_ciphertexts(
                mcl_from_str(seph, Fr), mcl_from_str(peph, G1),
                proper_keys[idx], mcl_from_str(client_eph, G1))
            ciphertexts.append([cip.hex() for cip in pair_ciphertexts])

        encoded_hex = [possibility.hex() for possibility in encoded]


        response = {}
        response["payload"] = {
            'ciphertexts': ciphertexts,
            'encoded': encoded_hex
        }

        try:
            db.session.delete(session_data)
            db.session.commit()
        except:
            current_app.logger.info(
                f"[{PROTOCOL_NAME}] cannot delete session data for {token=}")

        current_app.logger.info(
            f"[{PROTOCOL_NAME}] Sent response {response=}")

        return jsonify(response)


routes.append(dict(
    rule=f'/{PROTOCOL_NAME}/{PROTOCOL_ACTIONS[0]}',
    view_func=ot_circuit_init,
    options=dict(methods=['POST'])))

routes.append(dict(
    rule=f'/{PROTOCOL_NAME}/{PROTOCOL_ACTIONS[1]}',
    view_func=ot_circuit_send_values,
    options=dict(methods=['POST'])))
