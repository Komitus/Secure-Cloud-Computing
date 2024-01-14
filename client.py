import argparse
from client_apps.client_one_of_two import one_of_two
from client_apps.client_one_of_n import one_of_n
from client_apps.client_ope import ope_client

implemented_protocols = [
    "one_of_two",
    "one_of_n",
    "ope"
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
    "ope": ope_client
}


def main():
    arguments = parse_arg()
    protocols[arguments.protocol](arguments.url)


if __name__ == "__main__":
    main()
