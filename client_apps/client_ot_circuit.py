from routes.encoding_utils import *
from protocols import CircuitUser, OneOf2User
from globals import *
from mcl import G1

CHOOSEN_VALUES = [0, 1, 1, 1]


def ot_circuit(url):
    _PROTOCOL_NAME = Protocols.OT_CIRCUIT.value
    _PROTOCOL_ACTIONS = PROTOCOL_SPECS[_PROTOCOL_NAME]["actions"]
    payload_to_post = {
        "protocol_name": _PROTOCOL_NAME,
        "payload": {}
    }

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

    cloud_ephemerals = resp_data['payload']['pub_ephemerals']
    num_of_key_pairs = resp_data['payload']['circuit_len']
    print(f'{len(cloud_ephemerals)=}')
    assert num_of_key_pairs == len(CHOOSEN_VALUES)

    mcl_cloud_ephe = [mcl_from_str(cloud_eph, G1)
                      for cloud_eph in cloud_ephemerals]

    pub_client_ephemerals = []
    one_of_twos_list: list[OneOf2User] = []
    for msg_idx, cloud_eph in zip(CHOOSEN_VALUES, mcl_cloud_ephe):
        one_of_two_user = OneOf2User(msg_idx)
        pub_client_ephemerals.append(one_of_two_user.keygen(cloud_eph))
        one_of_twos_list.append(one_of_two_user)

    pub_client_ephemerals_strs = [mcl_to_str(peph)
                                  for peph in pub_client_ephemerals]
    payload_to_post['payload']['ephemerals'] = pub_client_ephemerals_strs

    resp_data = post_stage(
        url,
        _PROTOCOL_NAME,
        payload_to_post,
        _PROTOCOL_ACTIONS[1],
    )
    print(f'{resp_data=}')

    cloud_payload = resp_data.get('payload')
    ciphertexts = cloud_payload.get('ciphertexts')
    encoded = cloud_payload.get('encoded')
    encoded_bytes = [bytes.fromhex(possibility) for possibility in encoded]

    proper_keys = []
    for ciphertexts_pair, one_of_two_inst in zip(ciphertexts, one_of_twos_list):
        idx = one_of_two_inst.idx
        ciphertexts_pair_bytes = [bytes(), bytes()]
        ciphertexts_pair_bytes[idx] = bytes.fromhex(ciphertexts_pair[idx])
        proper_keys.append(one_of_two_inst.decrypt(ciphertexts_pair_bytes))

    print("RESULT:", CircuitUser.execute(
        encoded_bytes, proper_keys, CHOOSEN_VALUES))
