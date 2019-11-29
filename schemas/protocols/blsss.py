from bls_py import ec as bls
from bls_py.pairing import ate_pairing as e
import secrets
from schemas.utils import call_node, point_to_string_FQ, string_to_point_FQ2

class BLSSS:
    g = bls.generator_Fq()
    q = bls.bls12381.n

    @staticmethod
    def keygen():
        sk = secrets.randbelow(BLSSS.q)
        pk = BLSSS.g * sk
        return (sk, pk)
    
    @staticmethod
    def gen_g2_generator(msg):
        payload = [f'{msg}']
        return string_to_point_FQ2(call_node("./schemas/protocols/hash_map_g2.js", payload))
        
    @staticmethod
    def compute_sigma(h, sk):
        return h * sk

    @staticmethod
    def verify(sigma, A, h):
        return e(BLSSS.g, sigma) == e(A, h)