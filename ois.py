from py_ecc import bls12_381 as bls
from py_ecc.fields import bls12_381_FQ as FQ
import secrets
class OIS:
    g1 = bls.G1
    g2 = (
        FQ(2144250947445192081071618466765046647019257686245947349033844530891338159027816696711238671324221321317530545114427),
        FQ(2665798332422762660334686159210698639947668680862640755137811598895238932478193747736307724249253853210778728799013)
    )
    q = bls.curve_order

    @staticmethod
    def keygen():
        a_1 = secrets.randbelow(OIS.q)
        a_2 = secrets.randbelow(OIS.q)
        pk = bls.add(bls.multiply(OIS.g1,a_1),bls.multiply(OIS.g2,a_2))
        return ((a_1, a_2), pk)

    @staticmethod
    def gen_commit():
        x_1 = secrets.randbelow(OIS.q)
        x_2 = secrets.randbelow(OIS.q)
        big_X = bls.add(bls.multiply(OIS.g1,x_1),bls.multiply(OIS.g2,x_2))
        return ((x_1, x_2), big_X)

    @staticmethod
    def gen_challenge():
        return secrets.randbelow(OIS.q)

    @staticmethod
    def calc_proof(sk, x, c):
        s_1 = (x[0] + sk[0] * c) % OIS.q
        s_2 = (x[1] + sk[1] * c) % OIS.q
        return (s_1, s_2)

    @staticmethod
    def verify(A, X, c, s):
        return bls.add(bls.multiply(OIS.g1, s[0]), bls.multiply(OIS.g2, s[1])) == bls.add(X,bls.multiply(A,c))