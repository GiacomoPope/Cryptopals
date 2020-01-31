from s1c3 import crack_single_byte_xor, english_score

def find_xor_message(ciphertexts):
	best_guesses = []
	for c in ciphertexts:
		key, guess = crack_single_byte_xor(c)
		data = {
			'key' : key,
			'guess' : guess,
			'score' : english_score(guess),
		}
		best_guesses.append(data)
	best_guess = sorted(best_guesses, key=lambda x: x['score'])[-1]
	return best_guess['key'], best_guess['guess']

def main():
	ciphertexts = [line.strip() for line in open("s1c4.txt")]
	print(find_xor_message(ciphertexts))

if __name__ == '__main__':
	main()