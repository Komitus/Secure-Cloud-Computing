from py_ecc import bls12_381 as bls
import secrets
from utils import call_node, point_to_string_FQ, string_to_point_FQ2

class BLSSS:
    g = bls.G1
    q = bls.curve_order

    @staticmethod
    def keygen():
        sk = secrets.randbelow(BLSSS.q)
        pk = bls.multiply(BLSSS.g, sk)
        return (sk, pk)
    
    @staticmethod
    def gen_g2_generator(msg):
        payload = [f'{msg}']
        return string_to_point_FQ2(call_node("msis.js", payload))
        
    @staticmethod
    def compute_sigma(h, sk):
        return bls.multiply(h, sk)

    @staticmethod
    def verify(sigma, A, h):
        return bls.pairing(sigma, BLSSS.g) == bls.pairing(h, A)