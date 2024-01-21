import hashlib
import math
from typing import List
from mcl import *
from .protocols_utils import *
from .protocol_one_of_two import Q


class CircuitUser:

    def __init__(self):
        pass

    @staticmethod
    def execute(encoded_possibilities, keys, inputs: List[int]):
        # Convert binary inputs to an integer index
        index = int("".join(str(e) for e in inputs), 2)
        # Decode the received message using the outputs from oblivious transfer
        decoded = encoded_possibilities[index]
        for key in keys:
            decoded = decrypt(decoded, key)

        return int(decoded)


class CircuitCloud:
    """
    Server class for performing secure computation tasks.
    """

    def __init__(self, secret_circuit: list):
        """
        Initializes the Server instance.

        Args:
        secret_circuit (list): List representing the secret circuit for computation.
        """
        assert self.is_power_of_two(
            len(secret_circuit)), "Length of secret_circuit must be a power of 2."

        # Generate an element in G1 using the seed
        self.g__ = Q
        self.circuit = secret_circuit
        # Determine the number of bits required to represent all possible inputs
        self.number_of_possible_inputs = CircuitCloud.get_number_of_possible_inputs(
            self.circuit)
        self.keys = []

    @staticmethod
    def get_number_of_possible_inputs(circuit):
        return math.ceil(
            math.log2(len(circuit)))

    def gen_keys(self):
        """
        Generates cryptographic keys for each input bit.
        """
        # Generate a pair of keys for each bit in the input
        self.keys = [(self.key_gen(), self.key_gen())
                     for _ in range(self.number_of_possible_inputs)]

    def key_gen(self):
        """
        Generates a single cryptographic key.

        Returns:
        bytes: A generated cryptographic key.
        """
        # Generate a random element in Fr, multiply with g__, hash it and return
        return hashlib.sha256((self.g__ * Fr.rnd()).getStr()).digest()

    @staticmethod
    def get_encoded_and_keys(secret_circuit: list):
        # Initialize and prepare the server
        srv = CircuitCloud(secret_circuit)
        srv.gen_keys()

        encoded = []
        # Encode each value in the circuit
        for index, value in enumerate(srv.circuit):
            # Convert index to binary and pad with zeros
            bin_index = [int(a) for a in list(
                bin(index)[2:].zfill(srv.number_of_possible_inputs))]
            ciphertext = bytes(str(value).zfill(32), 'utf-8')
            # XOR the ciphertext with the appropriate keys
            for key_index in range(srv.number_of_possible_inputs):
                ciphertext = encrypt(
                    ciphertext, srv.keys[key_index][bin_index[key_index]])
            encoded.append(ciphertext)
        # Send the encoded data to the client
        return encoded, srv.keys

    @staticmethod
    def is_power_of_two(n: int) -> bool:
        """
        Checks if a number is a power of two.

        Args:
        n (int): The number to check.

        Returns:
        bool: True if n is a power of two, False otherwise.
        """
        return n != 0 and (n & (n - 1)) == 0
