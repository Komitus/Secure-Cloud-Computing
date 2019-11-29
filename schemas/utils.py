import subprocess
import secrets
from uuid import uuid4
from bls_py.ec import Fq, Fq2, AffinePoint
from bls_py.bls12381 import q
from base64 import b64decode, b64encode

def generate_token():
    return str(uuid4())

def point_to_string_FQ(point):
    return f'{point.x.Z} {point.y.Z}'
    # return str(point[0]) + " " + str(point[1])

def point_to_string_FQ2(point):
    point_str = f'{point.x.ZT} {point.y.ZT}'
    return point_str.translate(str.maketrans('', '', ',()'))

def string_to_point_FQ(str):
    point = str.split()
    args = [Fq(q, int(value)) for value in point]
    return AffinePoint(*args, False)

def string_to_point_FQ2(str):
    point = str.split()
    x = Fq2(q, *[Fq(q, int(value)) for value in point[:2]])
    y = Fq2(q, *[Fq(q, int(value)) for value in point[2:]])
    return AffinePoint(x, y, False)

def unpack(l):
    return ", ".join(map(str, l))

def call_node(filename, payload):
    params = ["node", filename] + payload
    
    a = subprocess.run(params, capture_output=True)
    return a.stdout.decode().strip("\n")

def read_key(key_name):
    with open(f"./schemas/{key_name}", "rb") as f:
        key = f.read()
        return key

def base64_encode(message):
    return b64encode(message)

def base64_decode(b64):
    return b64decode(b64)
