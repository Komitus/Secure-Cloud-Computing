from mcl import Fr

from protocols.protocol_psi import PSIServer, PSIUser


def test_si():

    x = {"a", "b", "c", "d"}
    y = {"c", "d", "e"}

    result_expected = len(x.intersection(y))

    server = PSIServer(list(map(lambda x: x.encode(), x)))
    user = PSIUser()
    user_enc_hashes = user.get_enc_hashes(list(map(lambda x: x.encode(), y)))

    processed_user_hashes, server_hashes = server.process_data_from_user(
        user_enc_hashes)

    result = user.calculate_set_intersection(
        processed_user_hashes, server_hashes)
    assert result == result_expected
