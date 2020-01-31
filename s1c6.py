from base64 import b64decode
from s1c3 import crack_single_byte_xor
from s1c5 import repeated_xor
from itertools import zip_longest

def hamming(b1,b2):
	distance = 0
	for a,b in zip(b1,b2):
		diff = a^b
		distance += sum(1 for bit in bin(diff) if bit == '1')
	return distance

def keylength(ciphertext):
	keyGuess = []
	for keysize in range(2,41):
		distances = []
		chunks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)]
		while len(chunks) > 2:
			s1 = chunks[0]
			s2 = chunks[1]
			distances.append(hamming(s1, s2) / keysize)
			del chunks[0]
			del chunks[1]
		data = {
			'keysize' : keysize,
			'avDistance' : sum(distances) / len(distances)
		}
		keyGuess.append(data)
	bestKey = sorted(keyGuess, key=lambda x: x['avDistance'])[0]
	return bestKey['keysize']

def break_repeating_xor(ciphertext): 
	key = b''
	n = keylength(ciphertext)
	blocks = [ciphertext[i:i+n] for i in range(0, len(ciphertext), n)]
	transposed_blocks = list(zip_longest(*blocks, fillvalue=0))
	for t in transposed_blocks:
		hexstring = ''.join(bytes([b]).hex() for b in t)
		key += bytes([crack_single_byte_xor(hexstring)[0]])
	
	message_bytes = repeated_xor(ciphertext, key)
	message = bytes.fromhex(message_bytes)
	return key, message


def main():
	a = b'this is a test'
	b = b'wokka wokka!!!'

	assert hamming(a,b) == 37

	with open("s1c6.txt") as input_file:
		cipher_bytes = b64decode(input_file.read())

	key, message = break_repeating_xor(cipher_bytes)

	print("Key found: \n", key.decode(), "Message: \n", message.decode(), sep='\n')

if __name__ == '__main__':
	main()