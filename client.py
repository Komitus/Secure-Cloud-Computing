import argparse

import requests
from py_ecc import bls12_381 as bls

from schemas.protocols import BLSSS, MSIS, OIS, SIS, GJSS, NAXOS, SSS
from schemas.utils import point_to_string_FQ, point_to_string_FQ2, string_to_point_FQ

implemented_protocols = ["sis", "ois", "sss", "msis", "blsss", "gjss", "naxos"]

def schnorr_is(url):
    sk, pk = SIS.keygen()
    x, big_x = SIS.gen_commit()
    init_json = {
        "protocol_name": "sis",
        "payload": {
            "A": point_to_string_FQ(pk),
            "X": point_to_string_FQ(big_x),
        }
    }
    res = requests.post(url=url + "/protocols/sis/init", json=init_json)
    data = res.json()
    c = int(data.get("payload").get("c"))
    token = data.get("session_token")
    s = SIS.calc_proof(sk, x, c)
    verify_json = {
        "protocol_name": "sis",
        "session_token": token,
        "payload": {
            "s": str(s)
        }
    }
    res = requests.post(url=url + "/protocols/sis/verify", json=verify_json)
    data = res.json()
    print(data)

def okamoto_is(url):
    sk, pk = OIS.keygen()
    x, big_x = OIS.gen_commit()
    init_json = {
        "protocol_name": "ois",
        "payload": {
            "A": point_to_string_FQ(pk),
            "X": point_to_string_FQ(big_x),
        }
    }
    res = requests.post(url=url + "/protocols/ois/init", json=init_json)
    data = res.json()
    c = int(data.get("payload").get("c"))
    token = data.get("session_token")
    s = OIS.calc_proof(sk, x, c)
    verify_json = {
        "protocol_name": "ois",
        "session_token": token,
        "payload": {
            "s1": str(s[0]),
            "s2": str(s[1]),
        }
    }
    res = requests.post(url=url + "/protocols/ois/verify", json=verify_json)
    data = res.json()
    print(data)

def schnorr_ss(url):
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
    res = requests.post(url=url + "/protocols/sss/verify", json=verify_json)
    data = res.json()
    print(data)

def mod_schnorr_is(url):
    sk, pk = MSIS.keygen()
    x, big_x = MSIS.gen_commit()
    init_json = {
        "protocol_name": "msis",
        "payload": {
            "A": point_to_string_FQ(pk),
            "X": point_to_string_FQ(big_x),
        }
    }
    res = requests.post(url=url + "/protocols/msis/init", json=init_json)
    data = res.json()
    c = int(data.get("payload").get("c"))
    token = data.get("session_token")
    g_hat = MSIS.gen_g2_generator(big_x, c)
    S = MSIS.calc_proof(g_hat, sk, x, c)
    verify_json = {
        "protocol_name": "msis",
        "session_token": token,
        "payload": {
            "S": point_to_string_FQ2(S)
        }
    }
    res = requests.post(url=url + "/protocols/msis/verify", json=verify_json)
    data = res.json()
    print(data)

def bls_ss(url):
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
    res = requests.post(url=url + "/protocols/blsss/verify", json=verify_json)
    data = res.json()
    print(data)

def gj_ss(url):
    message = "Test"
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
                "z": point_to_string_FQ2(z)
            },
            "A": point_to_string_FQ(pk),
            "msg": message
        }
    }
    res = requests.post(url=url + "/protocols/gjss/verify", json=verify_json)
    data = res.json()
    print(data)
    
def naxos_ake(url):
    message = "Test"
    sk, pk = NAXOS.keygen()
    ephemeral = NAXOS.gen_ephemeral(128)
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
    res = requests.post(url=url + "/protocols/naxos/exchange", json=exchange_json)
    data = res.json()
    Y = string_to_point_FQ(data.get("Y"))
    enc_msg = data.get("msg")
    K = NAXOS.calc_keyA(Y, sk, pk_b, ephemeral, pk)
    m = NAXOS.encode_msg(message, K)
    print(enc_msg == m)

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p", dest="protocol", choices=implemented_protocols, required=True)
    parser.add_argument("--u", dest="url", required=True)
    return parser.parse_args()

protocols = {
    "sis": schnorr_is,
    "ois": okamoto_is,
    "sss": schnorr_ss,
    "msis": mod_schnorr_is,
    "blsss": bls_ss,
    "gjss": gj_ss,
    "naxos": naxos_ake,
}

def main():
    arguments = parse_arg()
    protocols[arguments.protocol](arguments.url)

if __name__ == "__main__":
    main()
