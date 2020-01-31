from s2c10 import AES_CBC_encrypt, AES_CBC_decrypt
from Crypto.Util.number import long_to_bytes
import hashlib
from s5c33 import DiffieHellman
from Crypto import Random

block_size = 16

def key_from_secret(int_secret):
    bytes_secret = long_to_bytes(int_secret)
    sha1_secret = hashlib.sha1(bytes_secret).digest()
    key = sha1_secret[:block_size]
    return key

def protocol(alice,bob):
    # generate public keys
    A = alice.get_public_key()
    B = bob.get_public_key()

    # alice calculates the secret int and generates
    # 16 byte key from sha1 hash
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

    # bob takes the last 16 bytes to get the iv
    # then uses the remaining bytes as the encrypted
    # message
    a_iv = package_for_bob[-block_size : ]
    a_cipher = package_for_bob[:-block_size]

    # Using alice's public key, bob generates the
    # AES key
    bob_secret = bob.get_shared_secret(A)
    bob_key = key_from_secret(bob_secret)

    # bob decodes the message
    a_plaintext = AES_CBC_decrypt(a_cipher, bob_key, a_iv)

    # bob now generates a new IV and 
    # encrypts alice's message and 
    # sends this back to alice
    bob_iv = Random.new().read(block_size)
    bob_plaintext = AES_CBC_encrypt(a_plaintext, bob_key, bob_iv)

    # bob sends package to alice
    package_for_alice = bob_plaintext + bob_iv

    # alice recieves this package and 
    # checks if the messages are the same

    b_iv = package_for_alice[-block_size : ]
    b_cipher = package_for_alice[:-block_size]
    b_plaintext = AES_CBC_decrypt(b_cipher, alice_key, b_iv)

    assert alice_plaintext == b_plaintext

def MITM_attack(alice,bob):
    # generate public keys

    # The attack happens by eve listening
    # and waiting for the public key 
    # exchange. By replacing a with p
    # the shared secret beomes
    # s = p**X mod p = 0
    # this allows eve to calculate the key

    A = alice.get_public_key()
    # eve attacks by replacing A with p
    A = alice.p

    B = bob.get_public_key()
    # eve attacks by replacing B with p
    B = bob.p

    # alice calculates the secret int and generates
    # 16 byte key from sha1 hash
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

    # bob takes the last 16 bytes to get the iv
    # then uses the remaining bytes as the encrypted
    # message
    a_iv = package_for_bob[-block_size : ]
    a_cipher = package_for_bob[:-block_size]

    # Using alice's public key, bob generates the
    # AES key
    bob_secret = bob.get_shared_secret(A)
    bob_key = key_from_secret(bob_secret)

    # bob decodes the message
    a_plaintext = AES_CBC_decrypt(a_cipher, bob_key, a_iv)
    bob_plaintext = a_plaintext

    # bob now generates a new IV and 
    # encrypts alice's message and 
    # sends this back to alice
    bob_iv = Random.new().read(block_size)
    bob_ciphertext = AES_CBC_encrypt(bob_plaintext, bob_key, bob_iv)

    # bob sends package to alice
    package_for_alice = bob_ciphertext + bob_iv

    # alice recieves this package and 
    # checks if the messages are the same

    b_iv = package_for_alice[-block_size : ]
    b_cipher = package_for_alice[:-block_size]
    b_plaintext = AES_CBC_decrypt(b_cipher, alice_key, b_iv)

    assert alice_plaintext == b_plaintext

    # eve can listen in at any point

    eve_key = key_from_secret(0)

    eve1_iv = package_for_bob[-block_size : ]
    eve1_cipher = package_for_bob[:-block_size]
    eve1_plaintext = AES_CBC_decrypt(eve1_cipher, eve_key, eve1_iv)

    eve2_iv = package_for_alice[-block_size : ]
    eve2_cipher = package_for_alice[:-block_size]
    eve2_plaintext = AES_CBC_decrypt(eve2_cipher, eve_key, eve2_iv)

    assert eve1_plaintext ==  alice_plaintext
    assert eve2_plaintext ==  bob_plaintext

def main():
    alice = DiffieHellman()
    bob = DiffieHellman()
    protocol(alice,bob)
    MITM_attack(alice,bob)

if __name__ == '__main__':
    main()


