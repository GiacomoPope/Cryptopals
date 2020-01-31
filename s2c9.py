def pkcs7_pad(message, block_size=16):
    # return message if message size is equal to block size
    if len(message) % block_size == 0:
    	return message
    # add a padded byte equal to the number of bytes that need to be padded
    ch = block_size - len(message) % block_size
    return message + bytes([ch] * ch)

def is_pkcs7_padded(message):
	padding = message[-message[-1]:]
	return all(padding[i] == len(padding) for i in range(0,len(padding)))

def pkcs7_unpad(message, block_size=16):
	if len(message) == 0:
		raise Exception("The input data must contain at least one byte")

	if not is_pkcs7_padded(message):
		return message

	padding_len = message[-1]
	return message[:-padding_len]	
	
def main():
	block_size = 16
	message = b"YELLOW SUBMARINE"
	padded = pkcs7_pad(message, block_size)

	assert message == pkcs7_unpad(padded, block_size)

	print(padded)
	# print(is_pkcs7_padded(message))
	# print(is_pkcs7_padded(padded))
	# print(pkcs7_unpad(padded, block_size))

if __name__ == '__main__':
	main()