from base64 import b64encode

def main():
	hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
	hex_bytes = bytes.fromhex(hex_string)
	b64_string = b64encode(hex_bytes).decode()
	assert b64_string == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

if __name__ == '__main__':
	main()