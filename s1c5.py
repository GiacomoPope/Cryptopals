def repeated_xor(message, key):
	ciphertext = b''
	for i,c in enumerate(message):
		ciphertext += bytes([c ^ key[i % len(key)]])
	return(ciphertext.hex())

def main():
	message = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	check = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	key = b"ICE"
	assert check == repeated_xor(message, key)

if __name__ == '__main__':
	main()