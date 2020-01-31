def single_byte_xor(ciphertext, key):
    message_bytes = bytes.fromhex(ciphertext)
    plaintext = ""
    for b in message_bytes:
        plaintext += chr(b ^ key)
    return plaintext

def english_score(message):
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(c, 0) for c in message.lower()])

def crack_single_byte_xor(ciphertext):
    xor_scores = []
    for i in range(256):
        guess = single_byte_xor(ciphertext, i)
        data = {
            'key' : i,
            'score' : english_score(guess),
            'message' : guess
        }
        xor_scores.append(data)
    most_likely = sorted(xor_scores, key=lambda x: x['score'])[-1]
    return most_likely['key'], most_likely['message']

def main():
    ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    print(crack_single_byte_xor(ciphertext))

if __name__ == '__main__':
    main()