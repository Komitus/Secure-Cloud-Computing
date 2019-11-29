from bls_py import ec as bls

import secrets

class OIS:
    g1 = bls.generator_Fq()
    g2 = bls.AffinePoint(
        bls.Fq(bls.bls12381.q, 2144250947445192081071618466765046647019257686245947349033844530891338159027816696711238671324221321317530545114427),
        bls.Fq(bls.bls12381.q, 2665798332422762660334686159210698639947668680862640755137811598895238932478193747736307724249253853210778728799013),
        False
    )
    q = bls.bls12381.n

    @staticmethod
    def keygen():
        a_1 = secrets.randbelow(OIS.q)
        a_2 = secrets.randbelow(OIS.q)
        pk = (OIS.g1 * a_1) + (OIS.g2 * a_2)
        return ((a_1, a_2), pk)

    @staticmethod
    def gen_commit():
        x_1 = secrets.randbelow(OIS.q)
        x_2 = secrets.randbelow(OIS.q)
        big_X = (OIS.g1 * x_1) + (OIS.g2 * x_2)
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
        return (OIS.g1 * s[0]) + (OIS.g2 * s[1]) == X + (A * c)
