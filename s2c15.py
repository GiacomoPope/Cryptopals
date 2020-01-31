from s2c9 import *

assert is_pkcs7_padded(b'ICE ICE BABY\x04\x04\x04\x04') is True
assert is_pkcs7_padded(b'ICE ICE BABY\x05\x05\x05\x05') is False
assert is_pkcs7_padded(b'ICE ICE BABY\x01\x02\x03\x04') is False
assert is_pkcs7_padded(b'ICE ICE BABY') is False
assert pkcs7_unpad(b'ICE ICE BABY\x04\x04\x04\x04') == b'ICE ICE BABY'