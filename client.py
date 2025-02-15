import argparse
from client_apps.client_one_of_two import one_of_two
from client_apps.client_one_of_n import one_of_n
from client_apps.client_ope import ope_client
from client_apps.client_ot_circuit import ot_circuit
from client_apps.client_psi import psi

implemented_protocols = [
    "one_of_two",
    "one_of_n",
    "ope",
    "ot_circuit",
    "psi"
]


def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p", dest="protocol",
                        choices=implemented_protocols, required=True)
    parser.add_argument("--u", dest="url", required=True)
    return parser.parse_args()


protocols = {
    "one_of_two": one_of_two,
    "one_of_n": one_of_n,
    "ope": ope_client,
    "ot_circuit": ot_circuit,
    "psi": psi
}


def main():
    arguments = parse_arg()
    protocols[arguments.protocol](arguments.url)


if __name__ == "__main__":
    main()
