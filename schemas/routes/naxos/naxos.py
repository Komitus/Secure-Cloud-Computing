from schemas import db
from schemas.session import Session
from flask import request, current_app, jsonify
from schemas.protocols import NAXOS
from schemas.utils import string_to_point_FQ, point_to_string_FQ
from pprint import pformat

PROTOCOL = "naxos"
routes = []
naxos_sk, naxos_pk = NAXOS.keygen()

def naxos_pkey():
    current_app.logger.info(f"[NAXOS] Sent B:\n{pformat(naxos_pk)}")
    return jsonify({
        "B": point_to_string_FQ(naxos_pk)
    })

def naxos_exchange():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        current_app.logger.info(f"[NAXOS] Received payload:\n{pformat(payload)}")
        X = string_to_point_FQ(payload.get("X"))
        A = string_to_point_FQ(payload.get("A"))
        msg = payload.get("msg")
        ephemeral = NAXOS.gen_ephemeral(128)
        Y = NAXOS.calc_commit(ephemeral, naxos_sk)
        current_app.logger.info(f"[NAXOS] Calculated Y:\n{pformat(Y)}")
        K = NAXOS.calc_keyB(A, ephemeral, naxos_sk, X, naxos_pk)
        enc_msg = NAXOS.encode_msg(msg, K)
        return jsonify({
            "Y" : point_to_string_FQ(Y),
            "msg": enc_msg
        })
        
routes.append(dict(
    rule='/naxos/pkey',
    view_func=naxos_pkey,
    options=dict(methods=['GET'])))

routes.append(dict(
    rule='/naxos/exchange',
    view_func=naxos_exchange,
    options=dict(methods=['POST'])))