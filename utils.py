import secrets
from py_ecc.fields import bls12_381_FQ as FQ

def generate_token():
    return secrets.token_urlsafe(32)

def point_to_string(point):
    return str(point[0]) + " " + str(point[1])

def string_to_point(str):
    point = str.split()
    return tuple([FQ(int(coord)) for coord in point])

def unpack(l):
    return ", ".join(map(str, l))