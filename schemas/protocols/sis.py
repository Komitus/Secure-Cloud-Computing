from bls_py import ec as bls
import secrets

class SIS:
    g = bls.generator_Fq()
    q = bls.bls12381.n

    @staticmethod
    def keygen():
        sk = secrets.randbelow(SIS.q)
        pk = SIS.g * sk
        return (sk, pk)    
    
    @staticmethod
    def gen_commit():
        x = secrets.randbelow(SIS.q)
        big_X = SIS.g * x
        return (x, big_X)

    @staticmethod
    def gen_challenge():
        return secrets.randbelow(SIS.q)

    @staticmethod
    def verify(A, X, c, s):
        return SIS.g * s  == X + (A * c)

    @staticmethod
    def calc_proof(a, x, c):
        return (x + a * c) % SIS.q
