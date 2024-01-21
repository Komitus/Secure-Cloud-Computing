from protocols import CircuitCloud, CircuitUser
from itertools import product


def _binary_to_int(binary_array):
    length = len(binary_array)
    decimal_value = sum(
        [int(binary_array[i]) * (2 ** (length - i - 1)) for i in range(length)])
    return decimal_value


def test_ot_circuit_eval():
    n = 4
    all_possibilities = list(product([0, 1], repeat=n))
    for to_eval_from_client in all_possibilities:
        secret_circuit = [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1]
        encoded, keys = CircuitCloud.get_encoded_and_keys(secret_circuit)

        assert len(to_eval_from_client) == len(keys)
        keys_in_client = [key_pair[bit]
                          for bit, key_pair in zip(to_eval_from_client, keys)]

        result = CircuitUser.execute(
            encoded, keys_in_client, to_eval_from_client)
        assert result == secret_circuit[_binary_to_int(to_eval_from_client)]
