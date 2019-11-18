from schemas import db
from schemas.session import Session
from flask import request, current_app, jsonify
from schemas.protocols import GJSS
from schemas.utils import string_to_point_FQ, string_to_point_FQ2
from pprint import pformat

PROTOCOL = "gjss"
routes = []


def gjss_verify():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL:
        payload = data.get("payload")
        msg = payload.get("msg")
        current_app.logger.info(f"[GJSS] Received payload:\n{pformat(payload)}")
        A = string_to_point_FQ(payload.get("A"))
        sigma = payload.get("sigma")
        s = int(sigma.get("s"))
        c = int(sigma.get("c"))
        r = int(sigma.get("r"))
        z = string_to_point_FQ2(sigma.get("z"))
        h = GJSS.gen_h(msg, r)
        current_app.logger.info(f"[GJSS] Generated h:\n{pformat(h)}")
        u, v = GJSS.calc_commits(s, c, z, h, A)
        current_app.logger.info(f"[GJSS] Calculated u:\n{pformat(u)}\nv:\n{pformat(v)}")
        c_prim = GJSS.gen_challenge(h, A, z, u, v)
        current_app.logger.info(f"[GJSS] Generated c'\n{pformat(c)}")
        answer = GJSS.verify(c, c_prim)
        current_app.logger.info(f"[GJSS] Validation: {pformat(answer)}")
        return jsonify({
            "valid": answer
        })

routes.append(dict(
    rule='/gjss/verify',
    view_func=gjss_verify,
    options=dict(methods=['POST'])))