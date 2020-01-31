from base64 import b64decode
from Crypto.Cipher import AES
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

def get_blocks(data, block_size):
	return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def AES_ECB_decrypt(data, key):
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.decrypt(data)

def AES_ECB_encrypt(data, key):
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.encrypt(pkcs7_pad(data, block_size))

def generate_random(block_size):
	return os.urandom(16)

def ECB_oracle(data):
	plaintext = data + secret
	return AES_ECB_encrypt(plaintext,key)	

def find_block_length():
	input_data = b'A'
	ciphertext = ECB_oracle(input_data)
	length = len(ciphertext)
	new_length = length
	while length == new_length:
		input_data += b'A'
		ciphertext = ECB_oracle(input_data)
		new_length = len(ciphertext)
	return new_length - length

def detect_AES_Method(data):
	blocks = get_blocks(data, block_size)
	if len(blocks) != len(set(blocks)):
		return "ECB"
	return "CBC"

def find_byte(block_size, recovered):
	input_length = (block_size - (1 + len(recovered)))% block_size
	input_data = b'A' * input_length
	length_completed = input_length + len(recovered) + 1
	
	ciphertext = ECB_oracle(input_data)

	for i in range(256):
		guess = ECB_oracle(input_data + recovered + bytes([i]))
		if guess[:length_completed] == ciphertext[:length_completed]:
			return bytes([i])
	else:
		return b''

def crack_ECB_byte_by_byte():
	block_size = find_block_length()
	test_input = bytes([0]*64)
	assert detect_AES_Method(ECB_oracle(test_input)) == 'ECB'
	message_length = len(ECB_oracle(b''))
	recovered = b''
	for i in range(message_length):
		recovered += find_byte(block_size, recovered)
	return pkcs7_unpad(recovered)

block_size = 16
key = generate_random(block_size)

with open('s2c12.txt', 'r') as f:
	secret = b64decode(f.read())

print(crack_ECB_byte_by_byte().decode())











