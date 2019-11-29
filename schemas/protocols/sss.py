from bls_py import ec as bls
from hashlib import sha3_512
import secrets
from schemas.utils import point_to_string_FQ

class SSS:
    g = bls.generator_Fq()
    q = bls.bls12381.n

    @staticmethod
    def keygen():
        sk = secrets.randbelow(SSS.q)
        pk = SSS.g * sk
        return (sk, pk)    
    
    @staticmethod
    def gen_commit():
        x = secrets.randbelow(SSS.q)
        big_X = SSS.g * x
        return (x, big_X)

    @staticmethod
    def gen_challenge(m, X):
        return int(sha3_512((m + point_to_string_FQ(X)).encode()).hexdigest(),16) % SSS.q

    @staticmethod
    def calc_proof(a, x, c):
        return (x + a * c) % SSS.q

    @staticmethod
    def verify(A, X, c, s):
        return SSS.g * s  == X + (A * c)

