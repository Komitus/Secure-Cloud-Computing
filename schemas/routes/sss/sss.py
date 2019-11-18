from schemas import db
from schemas.session import Session
from flask import request, current_app, jsonify
from schemas.protocols import SSS
from schemas.utils import string_to_point_FQ
from pprint import pformat

PROTOCOL = "sss"
routes = []


def sss_verify():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        msg = payload.get("msg")
        current_app.logger.info(f"[SSS] Received payload:\n{pformat(payload)}")
        A = string_to_point_FQ(payload.get("A"))
        X = string_to_point_FQ(payload.get("X"))
        s = int(payload.get("s"))
        c = SSS.gen_challenge(msg, X)
        current_app.logger.info(f"[SSS] Generated c:\n{pformat(c)}")
        answer = SSS.verify(A, X, c, s)
        current_app.logger.info(f"[SSS] Validation: {pformat(answer)}")
        return jsonify({
            "valid": answer
        })

routes.append(dict(
    rule='/sss/verify',
    view_func=sss_verify,
    options=dict(methods=['POST'])))