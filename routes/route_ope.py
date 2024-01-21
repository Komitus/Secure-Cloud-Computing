"""
Route (server-side actions) for the oblivious
polynomial evaluation algorithm. The algorithm uses
uses 1-of-2 and 1-of-n oblivious transfers.
"""
from flask import request, current_app, jsonify
from db_model import db
from db_model import Session
from protocols import OpeCloud, OneOf2Cloud, OneOfNCloud
from protocols.protocol_ope import SEC_PARAM_N
from routes.encoding_utils import *
from pprint import pformat
from globals import *
from mcl import Fr

PROTOCOL_NAME = Protocols.OPE.value
PROTOCOL_ACTIONS = PROTOCOL_SPECS[PROTOCOL_NAME]["actions"]
routes = []

ALPHA = 10


def send_server_ephemeral():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL_NAME:
        zero = Fr()
        zero.setInt(0)
        alpha = Fr()
        alpha.setInt(ALPHA)
        opeCloud = OpeCloud()
        client_payload = data.get("payload")
        token = generate_token()

        current_app.logger.info(
            f"[one_of_two] Received payload:\n{pformat(client_payload)}")
        # Test prints
        # Print with red color

        current_app.logger.info(
            f'\033[91m THE ANSWER SHOULD BE {opeCloud.poly_p(alpha)=}\033[0m')

        # End of test prints

        query_points = client_payload.get('query_points')
        # query_points is a dict of values looking like this:
        # {
        #   'point_0_x': x_0,
        #   'point_0_y': y_0,
        #   ...
        #   'point_<N-1>_x': x_n,
        #   'point_<N-1>_y': y_n,
        # }
        query_points = [
            (
                mcl_from_str(query_points[f'point_{i}_x'], Fr),
                mcl_from_str(query_points[f'point_{i}_y'], Fr)
            )
            for i in range(len(query_points) // 2)
        ]

        # Returns only y-values, so the order of the
        # points is assumed to be the same as in the
        # request
        poly_q_values = opeCloud.generate_values_of_poly_q(query_points)

        assert len(query_points) == len(poly_q_values)

        # Generate gl.OPE_SMALL_N*bit_length(number_of_queried_points) public
        # ephemerals for the client to use in the OT protocol
        # print(f'{len(query_points).bit_length()=}')
        print(f'{SEC_PARAM_N=}')

        ephemerals = []
        for i in range(SEC_PARAM_N):
            for j in range(len(query_points).bit_length()):
                seph, peph = OneOf2Cloud.keygen()
                ephemerals.append((seph, peph))

        db_data = {
            'masked_poly_points': [],
            'ot_ephemerals': [],
        }
        for i in range(len(query_points)):
            db_data['masked_poly_points'].append(
                (mcl_to_str(query_points[i][0]),
                 mcl_to_str(poly_q_values[i]))
            )
        for i in range(len(ephemerals)):
            db_data['ot_ephemerals'].append(
                (mcl_to_str(ephemerals[i][0]), mcl_to_str(ephemerals[i][1]))
            )

        try:
            db.session.add(Session(session_token=token, payload=db_data))
            db.session.commit()
        except:
            db.create_all()
            db.session.rollback()
            current_app.logger.info(f"Bad session_token {token=}")

        response = {
            "session_token": token,
            "payload": {
                'pub_ephemerals': [
                    mcl_to_str(ephemerals[i][1])
                    for i in range(len(ephemerals))
                ]
            }
        }

        return jsonify(response)


def perform_n_of_big_n_ot():
    if request.data and type(request.data) is dict:
        data = request.data
    else:
        data = request.json
    if data.get("protocol_name") == PROTOCOL_NAME:
        client_payload = data.get("payload")
        token = data.get("session_token")

        client_ephemerals = client_payload.get('ephemerals')

        session_data = Session.query.filter_by(session_token=token).first()
        session_payload = session_data.payload
        points = session_payload.get('masked_poly_points')
        y_values_strs = [point[1] for point in points]
        y_value_bytes = [bytes.fromhex(y) for y in y_values_strs]

        total_num_of_points = len(y_values_strs)
        max_bits_in_point_idx = total_num_of_points.bit_length()
        number_of_requested_points = SEC_PARAM_N

        # Check that client_ephemerals is of the correct size.
        # Client ephemerals are a list of key-value pairs of the form:
        # {
        #   'ephemeral_<i>_<j>': <ephemeral_value>
        # }
        # where i is the index of the point and j is the index of the bit
        # of the point index.
        assert len(client_ephemerals) == \
            number_of_requested_points * max_bits_in_point_idx

        response_payload = {}
        for i in range(number_of_requested_points):
            one_of_n_cloud = OneOfNCloud(y_value_bytes)
            ciphertexts = one_of_n_cloud.gen_ciphertexts()
            i_keys = one_of_n_cloud.key_pairs
            response_payload[f'ciphertexts_{i}'] = \
                [cip.hex() for cip in ciphertexts]

            assert len(i_keys) == max_bits_in_point_idx
            for bit_i in range(max_bits_in_point_idx):
                seph, peph = session_payload['ot_ephemerals'][i *
                                                              max_bits_in_point_idx + bit_i]
                client_eph = client_ephemerals[f'ephemeral_{i}_{bit_i}']

                k_ciphertexts = OneOf2Cloud.gen_ciphertexts(mcl_from_str(seph, mcl.Fr), mcl_from_str(
                    peph, mcl.G1), i_keys[bit_i], mcl_from_str(client_eph, mcl.G1))

                response_payload[f'ciphertexts_{i}_{bit_i}'] = \
                    [cip.hex() for cip in k_ciphertexts]

        response = {}
        response["payload"] = response_payload

        try:
            db.session.delete(session_data)
            db.session.commit()
        except:
            current_app.logger.info(
                f"[{PROTOCOL_NAME}] cannot delete session data for {token=}")

        return jsonify(response)


routes.append(dict(
    rule=f'/{PROTOCOL_NAME}/{PROTOCOL_ACTIONS[0]}',
    view_func=send_server_ephemeral,
    options=dict(methods=['POST'])))

routes.append(dict(
    rule=f'/{PROTOCOL_NAME}/{PROTOCOL_ACTIONS[1]}',
    view_func=perform_n_of_big_n_ot,
    options=dict(methods=['POST'])))
