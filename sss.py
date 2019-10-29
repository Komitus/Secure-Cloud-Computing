from py_ecc import bls12_381 as bls
from hashlib import sha3_512
import secrets
from utils import point_to_string_FQ

class SSS:
    g = bls.G1
    q = bls.curve_order

    @staticmethod
    def gen_challenge(m, X):
        return int(sha3_512((m + point_to_string_FQ(X)).encode()).hexdigest(),16) % SSS.q

    @staticmethod
    def verify(A, X, c, s):
        return bls.multiply(SSS.g,s) == bls.add(X,bls.multiply(A,c))

    @staticmethod
    def keygen():
        sk = secrets.randbelow(SSS.q)
        pk = bls.multiply(SSS.g,sk)
        return (sk, pk)    
    
    @staticmethod
    def gen_commit():
        x = secrets.randbelow(SSS.q)
        big_X = bls.multiply(SSS.g,x)
        return (x, big_X)

    @staticmethod
    def calc_proof(a, x, c):
        return (x + a * c) % SSS.q
