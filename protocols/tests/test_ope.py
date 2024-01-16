from operator import itemgetter
from mcl import Fr
from protocols.protocol_ope import OpeCloud, OpeUser
from client_apps.client_ope import ope_client, ALPHA_VAL


def test_ope():
    zero = Fr()
    zero.setInt(0)
    opeCloud = OpeCloud()
    alpha = Fr()
    alpha.setInt(10)
    assert opeCloud.poly_x(zero) == zero
    opeUser = OpeUser(alpha)
    expected_val = opeCloud.poly_p(alpha)
    tags = opeUser.generate_xy()
    assert opeUser.poly_s(zero) == alpha
    poly_q_values = opeCloud.generate_values_of_poly_q(tags)
    choosen_poly_q_values = list(itemgetter(
        *opeUser.subset_of_n_indices)(poly_q_values))
    real_val = opeUser.calculate_poly_r(choosen_poly_q_values)
    assert expected_val == real_val


def test_client_ope():
    num_of_tests = 100
    alpha = Fr()
    alpha.setInt(ALPHA_VAL)
    opeCloud = OpeCloud()
    expected_val = opeCloud.poly_p(alpha)
    print(expected_val)
    for _ in range(num_of_tests):
        assert ope_client('http://192.168.0.39:8080') == expected_val
