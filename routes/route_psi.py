from flask import request, current_app, jsonify
from protocols import PSIServer
from routes.encoding_utils import *
from pprint import pformat
from globals import *
from mcl import G1


PROTOCOL_NAME = Protocols.PSI.value
PROTOCOL_ACTIONS = PROTOCOL_SPECS[PROTOCOL_NAME]["actions"]
routes = []

_ELEMENTS = [x.to_bytes(2, 'big') for x in range(100)]


def psi_send_hashes():
    print('here')
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL_NAME:
        payload = data.get("payload")
        current_app.logger.info(
            f"[si] Received payload:\n{pformat(payload)}")
        print(payload)
        elements_a = [mcl_from_str(a, G1) for a in payload['elements_a']]
        token = generate_token()
        server = PSIServer(_ELEMENTS)
        elements_a_prim, elements_t = server.process_data_from_user(elements_a)

        response = {
            "session_token": token,
            "payload": {
                "elements_a_prim": [mcl_to_str(a) for a in elements_a_prim],
                "elements_t": [mcl_to_str(a) for a in elements_t]
            },
        }

        return jsonify(response)


routes.append(dict(
    rule=f'/{PROTOCOL_NAME}/{PROTOCOL_ACTIONS[0]}',
    view_func=psi_send_hashes,
    options=dict(methods=['POST'])))
