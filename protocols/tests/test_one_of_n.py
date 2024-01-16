from protocols import OneOfNCloud, OneOfNUser
from .test_one_of_two import one_of_two_run_once
from routes.encoding_utils import mcl_to_str
from mcl import Fr
from protocols.protocols_utils import *
from secrets import SystemRandom


def _gen_example_msgs_keys(num_of_messages) -> list[bytes]:
    return [SystemRandom().randbytes(256) for _ in range(num_of_messages)]


def test_one_of_n_run_simulation():
    _NUM_OF_MESSAGES = 1000
    messages = _gen_example_msgs_keys(_NUM_OF_MESSAGES)
    cloud = OneOfNCloud(messages)
    ciphertexts = cloud.gen_ciphertexts()

    for user_idx in range(cloud.num_of_messages):
        user = OneOfNUser(user_idx, cloud.num_of_messages)
        for idx, keys in enumerate(cloud.key_pairs):
            bit_val = user.idx_bits_arr[idx]
            key = one_of_two_run_once(keys, bit_val)
            user.add_key(idx, key)
        # user.keys = [keys[bit_val]
        #     for keys, bit_val in zip(cloud.key_pairs, user.idx_bits_arr)]

        user.decrypt(
            ciphertexts[user_idx]) == cloud.messages[user_idx], f'{user_idx}'
