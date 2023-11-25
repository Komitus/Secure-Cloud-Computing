from mcl import G1
_SEC_PAR = b"test"
Q = G1.hashAndMapTo(_SEC_PAR)
from .protocol_one_of_two import OneOf2Cloud, OneOf2User
from .protocol_one_of_n import OneOfNCloud, OneOfNUser
