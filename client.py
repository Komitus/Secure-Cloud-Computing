import argparse
import requests
import json
from py_ecc import bls12_381 as bls
from schemas.cryptoboxs import Salsa, Chacha
from schemas.protocols import BLSSS, MSIS, OIS, SIS, GJSS, NAXOS, SSS, SIGMA
from schemas.utils import point_to_string_FQ, point_to_string_FQ2, string_to_point_FQ, read_key, base64_decode, base64_encode

implemented_protocols = ["all", "sis", "ois", "sss", "msis", "blsss", "gjss", "naxos", "sigma"]
salsa_key = read_key("salsa_key.bin")
salsabox = Salsa(salsa_key)
chacha_key = read_key("chacha_key.bin")
chachabox = Chacha(chacha_key)

def salsa_encrypt_json(js):
    bin_json = json.dumps(js).encode()
    cipher, nonce = salsabox.encrypt(bin_json)
    salsa_json = {
            "ciphertext": base64_encode(cipher).decode("utf-8"),
            "nonce": base64_encode(nonce).decode("utf-8"),
        }
    return salsa_json

def chacha_encrypt_json(js):
    bin_json = json.dumps(js).encode()
    cipher, tag, nonce = chachabox.encrypt(bin_json)
    chacha_json = {
        "ciphertext": base64_encode(cipher).decode("utf-8"),
        "tag": base64_encode(tag).decode("utf-8"),
        "nonce": base64_encode(nonce).decode("utf-8"),
    }
    return chacha_json

def salsa_decrypt_json(enc_data):
    res_cipher = base64_decode(enc_data.get("ciphertext"))
    res_nonce = base64_decode(enc_data.get("nonce"))
    enc_json = salsabox.decrypt(res_cipher, res_nonce)
    data = json.loads(enc_json.decode())
    return data

def chacha_decrypt_json(enc_data):
    req_cipher = base64_decode(enc_data.get("ciphertext"))
    req_nonce = base64_decode(enc_data.get("nonce"))
    req_tag = base64_decode(enc_data.get("tag"))
    enc_json = chachabox.decrypt(req_cipher, req_tag, req_nonce)
    data = json.loads(enc_json.decode())
    return data

def post_stage(url, cipher, protocol, json, stage):
    if cipher == "salsa":
        salsa_json = salsa_encrypt_json(json)
        res = requests.post(url=f'{url}/{cipher}/protocols/{protocol}/{stage}', json=salsa_json)
        enc_data = res.json()
        data = salsa_decrypt_json(enc_data)
    elif cipher == "chacha":
        chacha_json = chacha_encrypt_json(json)
        res = requests.post(url=f'{url}/{cipher}/protocols/{protocol}/{stage}', json=chacha_json)
        enc_data = res.json()
        data = chacha_decrypt_json(enc_data)
    else:
        res = requests.post(url=f'{url}/protocols/{protocol}/{stage}', json=json)
        data = res.json()
    return data


def schnorr_is(url, cipher):
    sk, pk = SIS.keygen()
    x, big_x = SIS.gen_commit()
    init_json = {
        "protocol_name": "sis",
        "payload": {
            "A": point_to_string_FQ(pk),
            "X": point_to_string_FQ(big_x),
        }
    }
    init_data = post_stage(url, cipher, "sis", init_json, "init")
    c = int(init_data.get("payload").get("c"))
    token = init_data.get("session_token")
    s = SIS.calc_proof(sk, x, c)
    verify_json = {
        "protocol_name": "sis",
        "session_token": token,
        "payload": {
            "s": str(s)
        }
    }
    data = post_stage(url, cipher, "sis", verify_json, "verify")
    print(data)

def okamoto_is(url, cipher):
    sk, pk = OIS.keygen()
    x, big_x = OIS.gen_commit()
    init_json = {
        "protocol_name": "ois",
        "payload": {
            "A": point_to_string_FQ(pk),
            "X": point_to_string_FQ(big_x),
        }
    }
    init_data = post_stage(url, cipher, "ois", init_json, "init")
    c = int(init_data.get("payload").get("c"))
    token = init_data.get("session_token")
    s = OIS.calc_proof(sk, x, c)
    verify_json = {
        "protocol_name": "ois",
        "session_token": token,
        "payload": {
            "s1": str(s[0]),
            "s2": str(s[1]),
        }
    }
    data = post_stage(url, cipher, "ois", verify_json, "verify")
    print(data)

def schnorr_ss(url, cipher):
    message = "Test"
    sk, pk = SSS.keygen()
    x, big_x = SSS.gen_commit()
    c = SSS.gen_challenge(message, big_x)
    s = SSS.calc_proof(sk, x, c)
    verify_json = {
        "protocol_name": "sss",
        "payload": {
            "s": str(s),
            "A": point_to_string_FQ(pk),
            "X": point_to_string_FQ(big_x),
            "msg": message
        }
    }
    data = post_stage(url, cipher, "sss", verify_json, "verify")
    print(data)

def mod_schnorr_is(url, cipher):
    sk, pk = MSIS.keygen()
    x, big_x = MSIS.gen_commit()
    init_json = {
        "protocol_name": "msis",
        "payload": {
            "A": point_to_string_FQ(pk),
            "X": point_to_string_FQ(big_x),
        }
    }
    init_data = post_stage(url, cipher, "msis", init_json, "init")
    c = int(init_data.get("payload").get("c"))
    token = init_data.get("session_token")
    g_hat = MSIS.gen_g2_generator(big_x, c)
    S = MSIS.calc_proof(g_hat, sk, x, c)
    verify_json = {
        "protocol_name": "msis",
        "session_token": token,
        "payload": {
            "S": point_to_string_FQ2(S)
        }
    }
    data = post_stage(url, cipher, "msis", verify_json, "verify")
    print(data)

def bls_ss(url, cipher):
    message = "Test"
    sk, pk = BLSSS.keygen()
    h = BLSSS.gen_g2_generator(message)
    sigma = BLSSS.compute_sigma(h, sk)
    verify_json = {
        "protocol_name": "blsss",
        "payload": {
            "sigma": point_to_string_FQ2(sigma),
            "A": point_to_string_FQ(pk),
            "msg": message
        }
    }
    data = post_stage(url, cipher, "blsss", verify_json, "verify")
    print(data)

def gj_ss(url, cipher):
    message = "message"
    sk, pk = GJSS.keygen()
    r = GJSS.gen_random(111)
    h = GJSS.gen_h(message, r)
    z = GJSS.compute_h_key(h, sk)
    k, u, v = GJSS.gen_commit(h)
    c = GJSS.gen_challenge(h, pk, z, u, v)
    s = GJSS.calc_proof(k, sk, c)
    verify_json = {
        "protocol_name": "gjss",
        "payload": {
            "sigma": {
                "s": str(s),
                "c": str(c),
                "r": str(r),
                "z": point_to_string_FQ(z)
            },
            "A": point_to_string_FQ(pk),
            "msg": message
        }
    }
    data = post_stage(url, cipher, "gjss", verify_json, "verify")
    print(data)
    
def naxos_ake(url, cipher):
    message = "Test"
    sk, pk = NAXOS.keygen()
    ephemeral = NAXOS.gen_ephemeral(128)
    if cipher == "salsa":
        res = requests.get(url=url + "/salsa/protocols/naxos/pkey")
        enc_data = res.json()
        data = salsa_decrypt_json(enc_data)
    elif cipher == "chacha":
        res = requests.get(url=url + "/chacha/protocols/naxos/pkey")
        enc_data = res.json()
        data = chacha_decrypt_json(enc_data)
    else:
        res = requests.get(url=url + "/protocols/naxos/pkey")
        data = res.json()
    pk_b = string_to_point_FQ(data.get("B"))
    X = NAXOS.calc_commit(ephemeral, sk)
    exchange_json = {
        "protocol_name": "naxos",
        "payload": {
            "X" : point_to_string_FQ(X),
            "A" : point_to_string_FQ(pk),
            "msg" : message 
        }
    }
    data = post_stage(url, cipher, "naxos", exchange_json, "exchange")
    Y = string_to_point_FQ(data.get("Y"))
    enc_msg = data.get("msg")
    K = NAXOS.calc_keyA(Y, sk, pk_b, ephemeral, pk)
    m = NAXOS.encode_msg(message, K)
    print(enc_msg == m)

def sigma_ake(url, cipher):
    message = "Test"
    sk, pk = SIGMA.keygen()
    x, X = SIGMA.gen_commit()
    init_json = {
        "protocol_name": "sigma",
        "payload": {
            "X": point_to_string_FQ(X),
        }
    }
    init_data = post_stage(url, cipher, "sigma", init_json, "init")
    token = init_data.get("session_token")
    payload = init_data.get("payload")
    pk_b = string_to_point_FQ(payload.get("B"))
    Y = string_to_point_FQ(payload.get("Y"))
    b_mac = payload.get("b_mac")
    sig_b = payload.get("sig")
    if sig_b.get("msg") is not None:
        sign_msg = sig_b.get("msg")
    else:
        sign_msg = point_to_string_FQ(X) + point_to_string_FQ(Y)
    sign_X = string_to_point_FQ(sig_b.get("X"))
    sign_s = int(sig_b.get("s"))
    assert(SIGMA.verify_signature(pk_b, sign_X, sign_s, sign_msg))
    mac_key = SIGMA.gen_mac_key(Y * x)
    assert(SIGMA.verify_mac(mac_key, point_to_string_FQ(pk_b), b_mac))
    sign_a_msg = point_to_string_FQ(Y) + point_to_string_FQ(X)
    signature = SIGMA.sign_message(sk, sign_a_msg)
    mac = SIGMA.auth_message(mac_key, point_to_string_FQ(pk))
    exchange_json = {
        "protocol_name": "sigma",
        "session_token": token,
        "payload": {
            "a_mac": mac,
            "A": point_to_string_FQ(pk),
            "msg": message,
            "sig": {
                "X": point_to_string_FQ(signature[0]),
                "s": str(signature[1]),
                "msg": sign_a_msg
            }
        }
    }
    data = post_stage(url, cipher, "sigma", exchange_json, "exchange")
    enc_msg = data.get("msg")
    K = SIGMA.gen_session_key(Y * x)
    m = SIGMA.encode_msg(message, K)
    print(enc_msg == m)



def make_all(url, cipher):
    r = requests.get(url=url + "/protocols/")
    data = r.json()
    schemas = data.get("schemas")
    for schema in schemas:
        protocol = protocols.get(schema)
        if protocol is not None:
            print(schema.upper())
            protocol(url, cipher)
        else:
            print(schema.upper(), "not implemented.")

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p", dest="protocol", choices=implemented_protocols, required=True)
    parser.add_argument("--u", dest="url", required=True)
    parser.add_argument("--c", dest="cipher", choices=["salsa", "chacha"], default=None)
    return parser.parse_args()

protocols = {
    "sis": schnorr_is,
    "ois": okamoto_is,
    "sss": schnorr_ss,
    "msis": mod_schnorr_is,
    "blsss": bls_ss,
    "gjss": gj_ss,
    "naxos": naxos_ake,
    "sigma": sigma_ake,
    "all": make_all
}

def main():
    arguments = parse_arg()
    protocols[arguments.protocol](arguments.url, arguments.cipher)

if __name__ == "__main__":
    main()
