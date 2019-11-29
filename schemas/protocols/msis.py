from bls_py import ec as bls
from bls_py.pairing import ate_pairing as e
import secrets
from schemas.utils import call_node, point_to_string_FQ, string_to_point_FQ2
class MSIS:
    g = bls.generator_Fq()
    q = bls.bls12381.n
    
    @staticmethod
    def keygen():
        sk = secrets.randbelow(MSIS.q)
        pk = MSIS.g * sk
        return (sk, pk)    
    
    @staticmethod
    def gen_commit():
        x = secrets.randbelow(MSIS.q)
        big_X = MSIS.g * x
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
        S = g_hat * s
        return S

    @staticmethod
    def verify(A, X, c, g_hat, S):
        return e(MSIS.g, S) == e(X + (A * c), g_hat)