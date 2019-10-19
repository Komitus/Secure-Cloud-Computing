from py_ecc import bls12_381 as bls
import secrets
class SIS:
    g = bls.G1
    q = bls.curve_order

    @staticmethod
    def gen_challenge():
        return secrets.randbelow(SIS.q)

    @staticmethod
    def verify(A, X, c, s):
        return bls.multiply(SIS.g,s) == bls.add(X,bls.multiply(A,c))

    @staticmethod
    def keygen():
        sk = secrets.randbelow(SIS.q)
        pk = bls.multiply(SIS.g,sk)
        return (sk, pk)    
    
    @staticmethod
    def gen_commit():
        x = secrets.randbelow(SIS.q)
        big_X = bls.multiply(SIS.g,x)
        return (x, big_X)

    @staticmethod
    def calc_proof(a, x, c):
        return (x + a * c) % SIS.q
