import secrets
from hashlib import sha3_512

from py_ecc import bls12_381 as bls

from schemas.utils import (call_node, point_to_string_FQ, point_to_string_FQ2,
                   string_to_point_FQ2, string_to_point_FQ)


class GJSS:
    g = bls.G1
    q = bls.curve_order

    @staticmethod
    def keygen():
        sk = secrets.randbelow(GJSS.q)
        pk = bls.multiply(GJSS.g, sk)
        return (sk, pk)

    @staticmethod
    def gen_random(bits):
        return secrets.randbits(bits)

    @staticmethod
    def gen_h(msg, r):
        payload = [f'{msg}{str(r)}']
        return string_to_point_FQ(call_node("./schemas/protocols/hash_map_g1.js", payload))
    
    @staticmethod
    def compute_h_key(h, x):
        return bls.multiply(h, x)
    
    @staticmethod
    def gen_commit(h):
        k = secrets.randbelow(GJSS.q)
        u = bls.multiply(GJSS.g, k)
        v = bls.multiply(h, k)
        return (k, u, v)

    @staticmethod
    def gen_challenge(h, Y, z, u, v):
        g_str = point_to_string_FQ(GJSS.g)
        h_str = point_to_string_FQ(h)
        Y_str = point_to_string_FQ(Y)
        z_str = point_to_string_FQ(z)
        u_str = point_to_string_FQ(u)
        v_str = point_to_string_FQ(v)
        points = g_str + h_str + Y_str + z_str + u_str + v_str
        return int(sha3_512((points).encode()).hexdigest(),16) % GJSS.q

    @staticmethod
    def calc_proof(k, x, c):
        return (k + x * c) % GJSS.q

    @staticmethod
    def calc_commits(s, c, z, h, y):
        u  = bls.add(bls.multiply(GJSS.g, s), bls.neg(bls.multiply(y, c)))
        v  = bls.add(bls.multiply(h, s), bls.neg(bls.multiply(z, c)))
        return (u, v)
    
    @staticmethod
    def verify(c, c_prim):
        return c ==  c_prim