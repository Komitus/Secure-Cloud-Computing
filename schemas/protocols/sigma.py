import secrets
from bls_py import ec as bls
from hashlib import sha3_512, sha3_256
from schemas.utils import point_to_string_FQ
from cryptography.hazmat.primitives import poly1305
from .sss import SSS
from base64 import b64encode, b64decode

class SIGMA:
    g = bls.generator_Fq()
    q = bls.bls12381.n
    
    @staticmethod
    def keygen():
        sk = secrets.randbelow(SIGMA.q)
        pk = SIGMA.g * sk
        return (sk, pk)

    @staticmethod
    def gen_commit():
        eph = secrets.randbelow(SIGMA.q)
        big_eph = SIGMA.g * eph
        return eph, big_eph
    
    @staticmethod
    def sign_message(sk, msg):
        x, X = SSS.gen_commit()
        c = SSS.gen_challenge(msg, X)
        s = SSS.calc_proof(sk, x, c)
        return (X, s)

    @staticmethod
    def verify_signature(pk, X, s, msg):
        c = SSS.gen_challenge(msg, X)
        return SSS.verify(pk,X,c,s)

    @staticmethod
    def gen_mac_key(value):
        return sha3_256(f'mac_{point_to_string_FQ(value)}'.encode()).digest()

    @staticmethod
    def auth_message(key, msg):
        return b64encode(poly1305.Poly1305.generate_tag(key, msg.encode())).decode("utf-8")

    @staticmethod
    def verify_mac(key, msg, tag):
        enc_tag = b64decode(tag)
        try:
            poly1305.Poly1305.verify_tag(key, msg.encode(), enc_tag)
            return True
        except:
            return False
    
    @staticmethod
    def gen_session_key(value):
        return sha3_256(f'session_{point_to_string_FQ(value)}'.encode()).digest()

    @staticmethod
    def encode_msg(msg, K):
        return b64encode(sha3_512(K + msg.encode()).digest()).decode("utf-8")