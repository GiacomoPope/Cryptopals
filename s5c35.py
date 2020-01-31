from s2c10 import AES_CBC_encrypt, AES_CBC_decrypt
from Crypto.Util.number import long_to_bytes
import hashlib
from s5c33 import DiffieHellman
from Crypto import Random

block_size = 16


"""
here we set g to three different values:

g = 1
g = p
g = p-1

by controlling g, we have the ability to know s

g = 1
A = g**a = 1, s = A**b = 1**b = 1

g = p
A = g**a = p**a, s = A**b = p**(a*b) = 0 mod p

g = p - 1
A = g**a = p**a, s = A**b = (p-1)**(a*b) = (-1)**(a*b) mod p
"""


def key_from_secret(int_secret):
    bytes_secret = long_to_bytes(int_secret)
    sha1_secret = hashlib.sha1(bytes_secret).digest()
    key = sha1_secret[:block_size]
    return key

def MITM_attack_g():
    p = DiffieHellman.NIST_p
    for g in [1,p,p-1]:
        # alice establishes parameters
        alice = DiffieHellman()

        # eve sends new value for g
        # bob creates parameters
        bob = DiffieHellman(g=g)

        # generate public keys
        A = alice.get_public_key()
        B = bob.get_public_key()

        # alice calculates the secret int and generates
        # 16 byte key from sha1 hash, but we now know
        # the value of alice's shared secret.
        # note: secrets shared between alice and bob are different as alice
        # cant have g replaced.
        alice_secret = alice.get_shared_secret(B)
        alice_key = key_from_secret(alice_secret)

        # alice generates a random IV and
        # encrypts a message using CBC
        alice_iv = Random.new().read(block_size)
        alice_plaintext = b'Hello Bob'
        alice_ciphertext = AES_CBC_encrypt(alice_plaintext, alice_key, alice_iv)
        # alice sends to bob her encrypted message with 
        # the iv appended

        package_for_bob = alice_ciphertext + alice_iv

        # bob cannot open this message, but eve can!

        eve_iv = package_for_bob[-block_size : ]
        eve_cipher = package_for_bob[:-block_size]

        if g == 1:
            eve_key = key_from_secret(1)
            eve_plaintext = AES_CBC_decrypt(eve_cipher, eve_key, eve_iv)
            assert eve_plaintext == alice_plaintext

        elif g == p:
            eve_key = key_from_secret(0)
            eve_plaintext = AES_CBC_decrypt(eve_cipher, eve_key, eve_iv)
            assert eve_plaintext == alice_plaintext

        elif g == p - 1:
            messages = []
            for i in [1,p-1]:
                eve_key = key_from_secret(i)
                eve_plaintext = AES_CBC_decrypt(eve_cipher, eve_key, eve_iv)
                messages.append(eve_plaintext)
            assert alice_plaintext in messages

def main():
    MITM_attack_g()

if __name__ == '__main__':
    main()


