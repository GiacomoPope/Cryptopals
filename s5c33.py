from random import randint

class DiffieHellman():
	NIST_p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
			'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
			'3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
			'6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
			'24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
			'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
			'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
			'fffffffffffff',16)
	NIST_g = 2

	def __init__(self, g=NIST_g, p=NIST_p):
		self.g = g
		self.p = p
		self.secret_int = randint(0, p-1)
		self.shared_key = None

	def get_public_key(self):
		return pow(self.g, self.secret_int, self.p)

	def get_shared_secret(self, recieved_public_key):
		if self.shared_key == None:
			shared_key = pow(recieved_public_key, self.secret_int, self.p)
		return shared_key

def main():
    alice = DiffieHellman()
    bob = DiffieHellman()

    assert alice.get_shared_secret(bob.get_public_key()) == bob.get_shared_secret(alice.get_public_key())

if __name__ == '__main__':
    main()