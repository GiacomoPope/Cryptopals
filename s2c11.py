from s2c9 import pkcs7_pad, pkcs7_unpad
from s2c10 import *
from base64 import b64decode
import os
from random import randint

def generate_random(block_size):
	return os.urandom(block_size)

def detect_AES_Method(data):
	blocks = get_blocks(data, block_size)
	if len(blocks) != len(set(blocks)):
		return "ECB"
	return "CBC"

def random_padding(data):
	x,y = randint(5,10), randint(5,10)
	return os.urandom(x) + data + os.urandom(y)

def encryption_oracle(data):
	key = generate_random(block_size)
	coin = randint(0,1)
	data = random_padding(data)

	if coin == 0:
		return "ECB", AES_ECB_encrypt(data, key)
	else:
		IV = generate_random(block_size)
		return "CBC", AES_CBC_encrypt(data, key, IV)

block_size = 16

if __name__ == '__main__':
	input_data = bytes([0]*64)
	for _ in range(100):
		method, ciphertext = encryption_oracle(input_data)
		check = detect_AES_Method(ciphertext)
		assert method == check



