from routes.encoding_utils import *
from protocols import OpeUser, OneOfNUser, OneOf2User
from protocols.protocol_ope import SEC_PARAM_BIG_N, SEC_PARAM_N
from globals import *
from mcl import Fr, G1

ALPHA_VAL = 10


def ope_client(url):
    alpha = Fr()
    alpha.setInt(ALPHA_VAL)
    _PROTOCOL_NAME = Protocols.OPE.value
    _PROTOCOL_ACTIONS = PROTOCOL_SPECS[_PROTOCOL_NAME]["actions"]
    payload_to_post = {
        "protocol_name": _PROTOCOL_NAME,
        "payload": {}
    }

    ### Query point generation ###
    ope_user = OpeUser(alpha)
    query_points = ope_user.generate_xy()

    payload_to_post['payload']['query_points'] = {}
    for (i, p) in enumerate(query_points):
        payload_to_post['payload']['query_points'][f'point_{i}_x'] = mcl_to_str(
            p[0])
        payload_to_post['payload']['query_points'][f'point_{i}_y'] = mcl_to_str(
            p[1])

    # print(f'{payload_to_post["payload"]["query_points"]=}')

    resp_data = post_stage(
        url,
        _PROTOCOL_NAME,
        payload_to_post,
        _PROTOCOL_ACTIONS[0],
    )

    print(f'{resp_data=}')
    token = resp_data.get('session_token')
    if token is None:
        raise Exception('No session token received')
    payload_to_post['session_token'] = token

    #### Generation of ephemerals for OT ####
    cloud_ephemerals = resp_data['payload']['pub_ephemerals']
    print(f'{len(cloud_ephemerals)=}')
    max_index_bit_len = SEC_PARAM_BIG_N.bit_length()
    submerged_ids = ope_user.subset_of_n_indices

    decryption_key_indices = {}
    ot_ephemerals = []
    payload_to_post['payload'].pop('query_points')
    payload_to_post['payload']['ephemerals'] = {}
    for i, subm in enumerate(submerged_ids):
        ot_idx_rev_bits = format(subm, 'b').zfill(max_index_bit_len)[::-1]
        decryption_key_indices[subm] = [
            int(bit) for bit in ot_idx_rev_bits
        ]

        for j in range(max_index_bit_len):
            choice = decryption_key_indices[subm][j]
            one_of_two_user = OneOf2User(choice)
            client_peph = one_of_two_user.keygen(mcl_from_str(
                cloud_ephemerals[i * max_index_bit_len + j],
                G1))
            enc_key = one_of_two_user._enc_key_bytes

            ot_ephemerals.append((enc_key, client_peph))
            payload_to_post['payload']['ephemerals'][f'ephemeral_{i}_{j}'] = mcl_to_str(
                client_peph)

    print(f'{payload_to_post["payload"]=}')
    resp_data = post_stage(
        url,
        _PROTOCOL_NAME,
        payload_to_post,
        _PROTOCOL_ACTIONS[1]
    )

    print(f'{resp_data=}')

    ####
    # Decryption of the selected polynomial points
    # and their interpolation
    ####
    # Format of the message:
    # {
    #   'ciphertexts_<i>': set of ciphertexts for the i-th point
    #                      out of the small_n needed
    #
    #   'ciphertexts_<i>_<bit_index>': two keys, one if index's bit
    #                                  on position bit_index is 0
    #                                  and the other if it is 1
    # }
    interpolation_set = []
    print(f'Interested in points: {submerged_ids}')
    for i in range(SEC_PARAM_N):
        ciphertexts = resp_data['payload'][f'ciphertexts_{i}']
        ciphertext_idx = submerged_ids[i]
        needed_point_ciphertext_bytes = bytes.fromhex(
            ciphertexts[ciphertext_idx]
        )
        print(f'Getting point number {needed_point_ciphertext_bytes=}')

        one_of_n_user = OneOfNUser(ciphertext_idx, SEC_PARAM_BIG_N)
        print(f'{ciphertexts=}')
        for j in range(max_index_bit_len):
            ciphertexts_keys = resp_data['payload'][f'ciphertexts_{i}_{j}']
            ciphertexts_keys_bytes = [bytes.fromhex(
                hex_string) for hex_string in ciphertexts_keys]

            # print(f'{ciphertexts_keys=}')
            key_idx = decryption_key_indices[ciphertext_idx][j]
            # print(f'{key_idx=}')
            (enc_key, client_peph) = ot_ephemerals[i * max_index_bit_len + j]
            # print(f'{enc_key=}')
            # print(f'{client_peph=}')
            one_of_two_user = OneOf2User(key_idx)
            one_of_two_user._enc_key_bytes = enc_key
            decrypted_key = one_of_two_user.decrypt(ciphertexts_keys_bytes)
            # print(f'key{decrypted_key=}')
            one_of_n_user.add_key(j, decrypted_key)

        # Decrypt the individual point from ciphertexts
        # using the keys
        decrypted_point = one_of_n_user.decrypt(
            needed_point_ciphertext_bytes)
        interpolation_set.append(decrypted_point)

    print(f'{interpolation_set=}')
    interpolation_set = [
        mcl_from_bytes(point, Fr) for point in interpolation_set
    ]

    result = ope_user.calculate_poly_r(
        interpolation_set
    )
    print(f'Evaluation result: {result=}')
    return result
