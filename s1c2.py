def xor_hex_strings(s1,s2):
	xor = int(s1,16) ^ int(s2,16)
	return '{:x}'.format(xor)

def main():
	s1 = '1c0111001f010100061a024b53535009181c'
	s2 = '686974207468652062756c6c277320657965'
	check = '746865206b696420646f6e277420706c6179'

	assert xor_hex_strings(s1,s2) == check

if __name__ == '__main__':
	main()