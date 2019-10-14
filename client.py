import requests
from sis import SIS
from py_ecc import bls12_381 as bls
import secrets
from utils import point_to_string
sk, pk = SIS.keygen()
x, big_x = SIS.gen_commit()
payload = {
    "A": point_to_string(pk),
    "X": point_to_string(big_x),
}
params = {"protocol_name": "sis", "payload": payload}
url = "http://knowak.thenflash.com/protocols/sis/init"
# url = "http://0.0.0.0:8080/protocols/sis/init"
res = requests.post(url=url, json=params)
data = res.json()
c = int(data.get("payload").get("c"))
token = data.get("session_token")

s = SIS.calc_proof(sk, x, c)

payload = {
    "s": str(s)
}

params = {"protocol_name": "sis", "session_token": token, "payload": payload}
url = "http://knowak.thenflash.com/protocols/sis/verify"
# url = "http://0.0.0.0:8080/protocols/sis/verify"
res = requests.post(url=url, json=params)
data = res.json()
print(data)