from s2c9 import pkcs7_pad, pkcs7_unpad
from Crypto.Cipher import AES
from base64 import b64decode, b64encode

block_size = 16

def get_blocks(data, block_size):
	return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def xor_bytes(data_1, data_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(data_1, data_2)])

def AES_ECB_decrypt(data, key):
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.decrypt(data)

def AES_ECB_encrypt(data, key):
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.encrypt(pkcs7_pad(data, block_size))

def AES_CBC_encrypt(data, key, IV):
	ciphertext = b''
	plain_blocks = get_blocks(pkcs7_pad(data,block_size), block_size)
	prev = IV
	for block in plain_blocks:
		cipher_block = AES_ECB_encrypt(xor_bytes(block, prev), key)
		ciphertext += cipher_block
		prev = cipher_block
	return ciphertext

def AES_CBC_decrypt(data,key,IV):
	plaintext = b''
	cipher_blocks = get_blocks(data, block_size)
	prev = IV
	for block in cipher_blocks:
		plain_block = xor_bytes(AES_ECB_decrypt(block, key), prev)
		plaintext += plain_block
		prev = block
	return pkcs7_unpad(plaintext)


if __name__ == '__main__':
	with open('s2c10.txt', 'r') as f:
		cipher = b64decode(f.read())

	#IV is nullbytes
	IV = bytes([0]*16)

	#key is given to us
	key = b'YELLOW SUBMARINE'

	#decode using CBC
	solution = AES_CBC_decrypt(cipher,key,IV)

	# check encryption works
	assert cipher == AES_CBC_encrypt(solution,key,IV)



