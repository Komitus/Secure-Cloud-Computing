import requests
import argparse
from sis import SIS
from utils import point_to_string

implemented_protocols = ["sis"]

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
    pass

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p", dest="protocol", choices=implemented_protocols, required=True)
    parser.add_argument("--u", dest="url", required=True)
    return parser.parse_args()

protocols = {
    "sis": schnorr_is,
    "ois": okamoto_is
}

def main():
    arguments = parse_arg()
    protocols[arguments.protocol](arguments.url)

if __name__ == "__main__":
    main()
