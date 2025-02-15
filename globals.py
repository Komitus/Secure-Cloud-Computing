from enum import Enum


class Protocols(Enum):
    ONE_OF_TWO = 'one_of_two'
    ONE_OF_N = 'one_of_n'
    OPE = 'ope'
    OT_CIRCUIT = "ot_circuit"
    PSI = "psi"

    @classmethod
    def has_value(cls, value):
        return value in cls._value2member_map_

    @classmethod
    def get_values(cls):
        return cls._value2member_map_.keys()

    @classmethod
    def get_as_list(cls):
        return list(cls._value2member_map_.keys())


# Actions are an ordered list of the requests (urls)
# sent by the client to the server
PROTOCOL_SPECS = {
    Protocols.ONE_OF_TWO.value: {
        'actions': [
            'get_A',
            'get_two_ciphertexts',
        ],
        'init_action': 'get_A',
        'close_action': 'get_two_ciphertexts'
    },
    Protocols.ONE_OF_N.value: {
        'actions': [
            'get_ciphertexts',
            'get_A',
            'get_two_ciphertexts',
            'done',
        ],
        'init_action': 'get_ciphertexts',
        'close_action': 'done'
    },
    Protocols.OPE.value: {
        'actions': [
            'get_server_ephemerals',
            'perform_n_of_big_n_ot',
        ],
        'init_action': 'get_server_ephemerals',
        'close_action': 'perform_n_of_big_n_ot',
    },
    Protocols.OT_CIRCUIT.value: {
        'actions': [
            'get_cloud_ephemerals',
            'get_encoded_values'
        ],
    },
    Protocols.PSI.value: {
        'actions': [
            'get_a_t',
            'done',
        ],
        'init_action': 'get_a_t',
        'close_action': 'done'
    }
}
