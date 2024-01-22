"""
Private Set Intersection protocol
"""
import random
from mcl import G1, Fr


class PSIServer:
    def __init__(self, elements: list[bytes]):
        self.__server_hashes = [G1.hashAndMapTo(
            element) for element in elements]
        random.shuffle(self.__server_hashes)

    def process_data_from_user(self, user_hashes: list[G1]):
        r_s = Fr.rnd()

        processed_user_hashes = [user_hash *
                                 r_s for user_hash in user_hashes]
        random.shuffle(user_hashes)
        server_hashes = [G1.hashAndMapTo((server_hash * r_s).getStr()) for server_hash in
                         self.__server_hashes]

        return processed_user_hashes, server_hashes


class PSIUser:
    def __init__(self):
        self.R_c = Fr.rnd()

    def calculate_set_intersection(self, user_hashes_processed_by_server: list[G1], server_hashes: list[G1]):
        one = Fr()
        one.setInt(1)
        return len({(G1.hashAndMapTo((user_hash * (one / self.R_c)).getStr())).getStr() for user_hash in
                    user_hashes_processed_by_server} & {server_hash.getStr() for server_hash in server_hashes})

    def get_enc_hashes(self, data):
        return [G1.hashAndMapTo(element)
                * self.R_c for element in data]
