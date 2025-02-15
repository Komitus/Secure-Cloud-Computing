from mcl import *
from .protocols_utils import *
from secrets import SystemRandom


class OneOfNCloud():
    def __init__(self, messages: bytes):
        self.messages = messages
        self.num_of_messages = len(self.messages)
        self.bitlength = int.bit_length(self.num_of_messages)
        self._rand_gen = SystemRandom()
        self.MSG_LEN = len(max(messages, key=len))  # bytes
        self.KEY_SIZE = self.MSG_LEN  # len(get_hash(b"test"))

        self._gen_key_pairs()

    def _gen_key_pairs(self) -> list[tuple[bytes, bytes]]:
        self.key_pairs = [(self._rand_gen.randbytes(self.KEY_SIZE),
                           self._rand_gen.randbytes(self.KEY_SIZE))
                          for _ in range(self.bitlength)]

    def gen_ciphertexts(self) -> list[bytes]:
        return [self._encrypt_one_msg(idx) for idx in range(self.num_of_messages)]

    def _encrypt_one_msg(self, msg_idx: int) -> bytes:
        result = self.messages[msg_idx]
        for key_idx in range(self.bitlength):
            curr_bit = msg_idx & 1
            msg_idx >>= 1
            _key = self.key_pairs[key_idx][curr_bit]
            result = encrypt(result, _key)
        return result


class OneOfNUser():
    def __init__(self, idx: int, no_of_msgs: int) -> None:
        self.idx = idx
        self.no_of_msgs = no_of_msgs
        self.bitlength = int.bit_length(no_of_msgs)
        self.keys = [bytes(b'')] * self.bitlength
        self.idx_bits_arr = [get_ith_bit(self.idx, i)
                             for i in range(self.bitlength)]

    def add_key(self, key_idx, key: bytes):
        self.keys[key_idx] = key

    def decrypt(self, ciphertext: bytes):
        result = ciphertext

        for _key in self.keys:
            result = decrypt(result, _key)

        return result
