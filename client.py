import requests
import argparse
from sis import SIS
from ois import OIS
from utils import point_to_string
from py_ecc import bls12_381 as bls

implemented_protocols = ["sis", "ois"]

def schnorr_is(url):
    sk, pk = SIS.keygen()
    x, big_x = SIS.gen_commit()
    init_json = {
        "protocol_name": "sis",
        "payload": {
            "A": point_to_string(pk),
            "X": point_to_string(big_x),
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
            "A": point_to_string(pk),
            "X": point_to_string(big_x),
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

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p", dest="protocol", choices=implemented_protocols, required=True)
    parser.add_argument("--u", dest="url", required=True)
    return parser.parse_args()

protocols = {
    "sis": schnorr_is,
    "ois": okamoto_is,
}

def main():
    arguments = parse_arg()
    protocols[arguments.protocol](arguments.url)

if __name__ == "__main__":
    main()
