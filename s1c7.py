from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from s2c9 import pkcs7_unpad

# Note:
# Is this solved, or should I go back and hand code AES-ECB?

def aes_ecb_decode(ciphertext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	plaintext = cipher.decrypt(ciphertext)
	return pkcs7_unpad(plaintext)

def main():
	key = b"YELLOW SUBMARINE"
	with open("s1c7.txt") as input_file:
		cipher_bytes = b64decode(input_file.read())
	plaintext = aes_ecb_decode(cipher_bytes, key)
	print(plaintext.decode())

if __name__ == '__main__':
	main()