import subprocess
import secrets
from uuid import uuid4
from py_ecc.fields import bls12_381_FQ as FQ, bls12_381_FQ2 as FQ2
from base64 import b64decode, b64encode

def generate_token():
    return str(uuid4())

def point_to_string_FQ(point):
    return str(point[0]) + " " + str(point[1])

def point_to_string_FQ2(point):
    return str(point).translate(str.maketrans('', '', ',()'))

def string_to_point_FQ(str):
    point = str.split()
    return tuple([FQ(int(coord)) for coord in point])

def string_to_point_FQ2(str):
    point = str.split()
    x = [int(coord) for coord in point[:2]]
    y = [int(coord) for coord in point[2:]]
    # import pdb; pdb.set_trace()
    return (FQ2(x), FQ2(y))

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
