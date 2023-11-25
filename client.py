import argparse
from schemas.client_apps.client_one_of_two import one_of_two
from schemas.client_apps.client_one_of_n import one_of_n

implemented_protocols = ["one_of_two", "one_of_n"]


def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p", dest="protocol",
                        choices=implemented_protocols, required=True)
    parser.add_argument("--u", dest="url", required=True)
    return parser.parse_args()


protocols = {
    "one_of_two": one_of_two,
    "one_of_n": one_of_n,
}


def main():
    arguments = parse_arg()
    protocols[arguments.protocol](arguments.url)


if __name__ == "__main__":
    main()
