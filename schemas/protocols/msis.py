from py_ecc import bls12_381 as bls
import secrets
from schemas.utils import call_node, point_to_string_FQ, string_to_point_FQ2
class MSIS:
    g = bls.G1
    q = bls.curve_order

    
    @staticmethod
    def keygen():
        sk = secrets.randbelow(MSIS.q)
        pk = bls.multiply(MSIS.g,sk)
        return (sk, pk)    
    
    @staticmethod
    def gen_commit():
        x = secrets.randbelow(MSIS.q)
        big_X = bls.multiply(MSIS.g,x)
        return (x, big_X)

    @staticmethod
    def gen_challenge():
        return secrets.randbelow(MSIS.q)

    @staticmethod
    def gen_g2_generator(X, c):
        x_str = point_to_string_FQ(X)
        payload = [f'{x_str}{str(c)}']
        return string_to_point_FQ2(call_node("./schemas/protocols/hash_map_g2.js", payload))

    @staticmethod
    def calc_proof(g_hat, a, x, c):
        s = (x + a * c) % MSIS.q
        S = bls.multiply(g_hat, s)
        return S

    @staticmethod
    def verify(A, X, c, g_hat, S):
        return bls.pairing(S, MSIS.g) == bls.pairing(g_hat, bls.add(X, bls.multiply(A, c)))
