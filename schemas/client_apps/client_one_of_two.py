from schemas.encoding_utils import *
from schemas.protocols.protocol_one_of_two import OneOf2User

_CLIENT_IDX = 1

def one_of_two(url):
    client_idx = _CLIENT_IDX
    init_dic = {
        "protocol_name": "one_of_two",
        "payload": {}
    }
    resp_data = post_stage(url, "one_of_two", init_dic, "get_A")
    token = resp_data.get("session_token")
    big_a = mcl_from_str(resp_data.get("payload").get("A"), mcl.G1)
    user = OneOf2User(client_idx)

    init_dic['session_token'] = token
    init_dic['payload']['B'] = mcl_to_str(user.keygen(big_a))

    resp_data = post_stage(url, "one_of_two", init_dic, "get_ciphertexts")
    ciphertext_in_hex: list[str] = resp_data.get("payload").get("ciphertexts")
    ciphertexts_in_bytes = [bytes.fromhex(
        hex_string) for hex_string in ciphertext_in_hex]

    print(f"MSG: {user.decrypt(ciphertexts_in_bytes)}")
