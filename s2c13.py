from Crypto.Cipher import AES
import os

def generate_random(block_size):
	return os.urandom(16)

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

def AES_ECB_decrypt(data, key):
	cipher = AES.new(key, AES.MODE_ECB)
	return pkcs7_unpad(cipher.decrypt(data))

def AES_ECB_encrypt(data, key):
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.encrypt(pkcs7_pad(data, block_size))

def kvparse_encode(d):
	encoded = ''
	for k,v in d.items():
		encoded += k + '=' + str(v) + '&'
	return encoded[:-1]

def kvparse_decode(s):
	d = {}
	kvpairs = s.split('&')
	for pair in kvpairs:
		vals = pair.split('=')
		if vals[1].isdigit():
			d.update( {vals[0] : int(vals[1])} )
		else:
			d.update( {vals[0] : vals[1]} )
	return d

def profile_for(s):
	s = s.replace('&','').replace('=','')
	profile = {
	'email' : s,
	'uid' : 10,
	'role' : 'user'
	}
	return kvparse_encode(profile).encode()



block_size = 16
key = generate_random(block_size)

email = 'hello@gmail.com'

cipher = AES_ECB_encrypt(profile_for(email), key)
assert AES_ECB_decrypt(cipher, key) == profile_for(email)

#block layout
#000000000000000011111111111111112222222222222222
#email=XXXXXXXXXXXXX&uid=10&role=user
#000000000000000011111111111111112222222222222222
#email=XXXXXXXXXXadminXXXXXXXXXXX&uid=10&role=user

def ECB_cut_and_paste(role):
	email_1 = 'hi@google.com'
	cipher_1 = AES_ECB_encrypt(profile_for(email_1), key)

	extra_pad = block_size - len(role)
	email_2 = 'X'*(block_size - len('email=')) + role + chr(extra_pad)*extra_pad
	cipher_2 = AES_ECB_encrypt(profile_for(email_2), key)

	cut_paste = cipher_1[:32]+cipher_2[16:32]
	return AES_ECB_decrypt(cut_paste, key)

cutup = ECB_cut_and_paste('king_jack').decode()

print(kvparse_decode(cutup))
