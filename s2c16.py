from Crypto.Cipher import AES
from base64 import b64decode
import os

def pkcs7_pad(message, block_size):
    if len(message) % block_size == 0:
    	return message
    ch = block_size - len(message) % block_size
    return message + bytes([ch] * ch)

def is_pkcs7_padded(data):
	padding = data[-data[-1]:]
	return all(padding[b] == len(padding) for b in range(len(padding)))

def pkcs7_unpad(data):
	if len(data) == 0:
		return "Data must have at least one byte"
	if not is_pkcs7_padded(data):
		return data
	pad_bytes = data[-1]
	return data[:-pad_bytes]

def generate_random(block_size):
	return os.urandom(16)

def get_blocks(data, block_size):
	return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def xor_data(data_1, data_2):
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
		cipher_block = AES_ECB_encrypt(xor_data(block, prev), key)
		ciphertext += cipher_block
		prev = cipher_block
	return ciphertext

def AES_CBC_decrypt(data,key,IV):
	plaintext = b''
	cipher_blocks = get_blocks(data, block_size)
	prev = IV
	for block in cipher_blocks:
		plain_block = xor_data(AES_ECB_decrypt(block, key), prev)
		plaintext += plain_block
		prev = block
	return plaintext

def find_block_length(cbc_oracle):
	input_data = 'A'
	ciphertext = cbc_oracle.CBC_encrypt(input_data)
	length = len(ciphertext)
	new_length = length
	while length == new_length:
		input_data += 'A'
		ciphertext = cbc_oracle.CBC_encrypt(input_data)
		new_length = len(ciphertext)
	return new_length - length

def find_prefix_length(cbc_oracle):
	ciphertext_1 = cbc_oracle.CBC_encrypt('A')
	ciphertext_2 = cbc_oracle.CBC_encrypt('B')

	# find the block where the prefix ends
	block_position = 0
	while ciphertext_1[block_position] == ciphertext_2[block_position]:
		block_position += 1
	block_position = (block_position // block_size ) * block_size

	# find where in the block the prefix ends
	for i in range(1,block_size+1):
		ciphertext_1 = cbc_oracle.CBC_encrypt('A' * i + 'B')
		ciphertext_2 = cbc_oracle.CBC_encrypt('A' * i + 'C')
		if ciphertext_1[block_position:block_position+block_size] == ciphertext_2[block_position:block_position+block_size]:
			return block_position + (block_size - i)

class Oracle:
	def __init__(self):
		self.key = generate_random(block_size)
		self.IV = generate_random(block_size)
		self.prefix = "comment1=cooking%20MCs;userdata="
		self.suffix = ";comment2=%20like%20a%20pound%20of%20bacon"

	def CBC_encrypt(self, input_data):
		input_data = input_data.replace(';','').replace('=','')
		data = (self.prefix + input_data + self.suffix).encode()
		return AES_CBC_encrypt(data, self.key, self.IV)

	def CBC_decrypt(self, ciphertext):
		plaintext = AES_CBC_decrypt(ciphertext, self.key, self.IV)
		return b';admin=true;' in plaintext, plaintext


def CBC_bit_flip(cbc_oracle, goal):
	user = '?'*len(goal)
	#find the block size and prefix, assuming these are unknown
	block_size = find_block_length(cbc_oracle)
	prefix_length = find_prefix_length(cbc_oracle)

	assert len(goal) < block_size, 'Length of attack text is longer than the block size.'

	#Attack text pads the prefix to a block length, adds a block bytes to be bit flipped and then
	#enters the user data which contains characters that evade the filters. User input data
	#is also padding as a prefix to be of block length

	attack_text = 'P' * (block_size - prefix_length%block_size) + 'X' * block_size + 'Y' * (block_size - len(user)) + user
	ciphertext = cbc_oracle.CBC_encrypt(attack_text)
	cipher_bytes = list(ciphertext)	

	#Calculates the position where the user data starts to allow us to flip the corresponding bits
	#in the padding block

	offset = prefix_length + (block_size - prefix_length%block_size) + (block_size - len(user))

	#Goes through the user data and XORs the preceeding block correctly to affect the following block, changing the data
	for i in range(len(goal)):
		cipher_bytes[offset + i] = cipher_bytes[offset + i] ^ ord(goal[i]) ^ ord(user[i])
	return bytes(cipher_bytes)

block_size = 16
cbc_oracle = Oracle()

attacked_ciphertext = CBC_bit_flip(cbc_oracle, ';admin=true;')
print(cbc_oracle.CBC_decrypt(attacked_ciphertext))




