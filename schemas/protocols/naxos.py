import secrets
from py_ecc import bls12_381 as bls
from hashlib import sha3_512
from schemas.utils import point_to_string_FQ
from base64 import b64encode

class NAXOS:
    g = bls.G1
    q = bls.curve_order

    @staticmethod
    def keygen():
        sk = secrets.randbelow(NAXOS.q)
        pk = bls.multiply(NAXOS.g,sk)
        return (sk, pk)

    @staticmethod
    def gen_ephemeral(lamb):
        return secrets.randbits(lamb)
    
    @staticmethod
    def H1(str):
        return int(sha3_512(str.encode()).hexdigest(),16) % NAXOS.q
    
    @staticmethod
    def calc_commit(ephemeral, sk):
        h = NAXOS.H1((str(ephemeral) + str(sk)))
        return bls.multiply(NAXOS.g, h)

    @staticmethod
    def H2(str):
        return sha3_512(str.encode()).digest()

    @staticmethod
    def calc_keyB(pk_a, esk_b, sk_b, X, pk_b):
        h = NAXOS.H1((str(esk_b) + str(sk_b)))
        pk_a_hash = point_to_string_FQ(bls.multiply(pk_a, h))
        X_sk_b = point_to_string_FQ(bls.multiply(X, sk_b))
        X_hash = point_to_string_FQ(bls.multiply(X, h))
        return NAXOS.H2(pk_a_hash + X_sk_b + X_hash + point_to_string_FQ(pk_a) + point_to_string_FQ(pk_b))

    @staticmethod
    def calc_keyA(Y, sk_a, pk_b, esk_a, pk_a):
        h = NAXOS.H1((str(esk_a) + str(sk_a)))
        Y_sk_a = point_to_string_FQ(bls.multiply(Y, sk_a))
        pk_b_hash = point_to_string_FQ(bls.multiply(pk_b, h))
        Y_hash = point_to_string_FQ(bls.multiply(Y, h))
        return NAXOS.H2(Y_sk_a + pk_b_hash + Y_hash + point_to_string_FQ(pk_a) + point_to_string_FQ(pk_b))

    @staticmethod
    def encode_msg(msg, K):
        return b64encode(sha3_512(K + msg.encode()).digest()).decode("utf-8")
        
