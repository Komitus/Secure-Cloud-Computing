from mcl import G1
from routes.encoding_utils import *
from globals import *
from protocols import PSIUser


def psi(url):
    _ELEMENTS = [x.to_bytes(2, 'big') for x in range(80, 150)]
    client = PSIUser()

    _PROTOCOL_NAME = Protocols.PSI.value
    _PROTOCOL_ACTIONS = PROTOCOL_SPECS[_PROTOCOL_NAME]["actions"]
    init_dic = {
        "protocol_name": _PROTOCOL_NAME,
        "payload": {
            "elements_a": [mcl_to_str(a) for a in client.get_enc_hashes(_ELEMENTS)]
        }
    }
    print(url, _PROTOCOL_NAME, init_dic, _PROTOCOL_ACTIONS[0])
    resp_data = post_stage(url, _PROTOCOL_NAME, init_dic,
                           _PROTOCOL_ACTIONS[0])

    print(f'{resp_data["payload"]=}')
    elements_a_prim = [mcl_from_str(a, G1)
                       for a in resp_data["payload"]["elements_a_prim"]]
    elements_ts = [mcl_from_str(a, G1)
                   for a in resp_data["payload"]["elements_t"]]

    result = client.calculate_set_intersection(elements_a_prim, elements_ts)
    print(f"# common elements: {result}")
