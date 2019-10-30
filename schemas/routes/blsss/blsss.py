from schemas import db
from schemas.session import Session
from flask import request, current_app, jsonify
from schemas.protocols import BLSSS
from schemas.utils import string_to_point_FQ, string_to_point_FQ2
from pprint import pformat

PROTOCOL = "blsss"
routes = []


def blsss_verify():
    data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        msg = payload.get("msg")
        current_app.logger.info(f"[BLSSS] Received payload:\n{pformat(payload)}")
        A = string_to_point_FQ(payload.get("A"))
        sigma = string_to_point_FQ2(payload.get("sigma"))
        h = BLSSS.gen_g2_generator(msg)
        current_app.logger.info(f"[BLSSS] Generated h:\n{pformat(h)}")
        answer = BLSSS.verify(sigma, A, h)
        current_app.logger.info(f"[BLSSS] Validation: {pformat(answer)}")
        return jsonify({
            "valid": answer
        })

routes.append(dict(
    rule='/blsss/verify',
    view_func=blsss_verify,
    options=dict(methods=['POST'])))