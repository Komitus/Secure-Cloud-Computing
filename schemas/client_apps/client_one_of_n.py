from schemas.encoding_utils import *
from schemas.protocols.protocol_one_of_two import OneOf2User
from schemas.protocols.protocol_one_of_n import OneOfNUser

_CLIENT_IDX = 8


def one_of_n(url):
    client_idx = _CLIENT_IDX
    init_dic = {
        "protocol_name": "one_of_n",
        "payload": {}
    }
    resp_data = post_stage(url, "one_of_n", init_dic, "get_ciphertexts")
    token = resp_data["session_token"]
    tmp_ciphertexts = resp_data["payload"]["ciphertexts"]
    num_of_messages = len(tmp_ciphertexts)
    assert client_idx < num_of_messages
    init_dic['session_token'] = token

    main_ciphertext = bytes.fromhex(tmp_ciphertexts[client_idx])
    tmp_ciphertexts = []
    one_of_n_user = OneOfNUser(client_idx, num_of_messages)

    # one of two part

    for key_idx in range(one_of_n_user.bitlength):
        tmp_client_idx = one_of_n_user.idx_bits_arr[key_idx]
        one_of_two_user = OneOf2User(tmp_client_idx)
        resp_data = post_stage(url, "one_of_n", init_dic, "get_A")
        big_a = mcl_from_str(resp_data["payload"]["A"], mcl.G1)
        big_b = one_of_two_user.keygen(big_a)
        one_of_two_payload = {
            "protocol_name": "one_of_n",
            "payload": {
                "B": mcl_to_str(big_b),
                "key_idx": key_idx,
            },
            "session_token": token,
        }

        resp_data = post_stage(
            url, "one_of_n", one_of_two_payload, "get_two_ciphertexts")

        one_of_two_ciphertexts = [bytes.fromhex(
            cip) for cip in resp_data["payload"]['ciphertexts']]

        key = one_of_two_user.decrypt(one_of_two_ciphertexts)
        one_of_n_user.add_key(key_idx, key)

    print(f"MSG: {one_of_n_user.decrypt(main_ciphertext)}")
