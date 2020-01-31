block_size = 16

def count_repeating_blocks(ciphertext):
	blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
	# print(blocks)
	return len(blocks) - len(set(blocks))

def find_ecb(ciphertexts):
	cipher_info = []
	for i, c in enumerate(ciphertexts):
		data = {
			'location' : i,
			'repetitions' : count_repeating_blocks(c)
		}
		cipher_info.append(data)/Users/Jack/Documents/GitHub/Cryptopals/s2c9.py
	most_likely = sorted(cipher_info, key=lambda x: x['repetitions'])[-1]
	return most_likely['location'], ciphertexts[most_likely['location']]

def main():
	key = b"YELLOW SUBMARINE"
	ciphertexts = [bytes.fromhex(line.strip()) for line in open("s1c8.txt")]
	location, ciphertext = find_ecb(ciphertexts)
	print(location)

if __name__ == '__main__':
	main()