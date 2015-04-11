#!/usr/bin/env python

import string  # for printable
import random  # for randint
from Crypto.Cipher import AES  # pip install PyCrypto

def bytes_to_base64_array(bytes):
    r = []
    for i in range(0, len(bytes), 3):
       # c is a 24bit representation of three input bytes
       c = 0
       for j in range(3):
          c += bytes[i + j] << (16 - 8 * j)
       for j in range(4):
          r.append(0x3F & (c >> (18 - 6 * j)))
    return r

def base64_array_to_base64(b64_array):
    r = ""
    D = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for c in b64_array:
	r += D[c]
    return r

def bytes_to_base64(bytes):
    return base64_array_to_base64(bytes_to_base64_array(bytes))

def hex_to_bytes(hex):
    r = []
    for i in range(0, len(hex), 2):
        r.append((int(hex[i], 16) << 4) + int(hex[i + 1], 16))
    return r

def bytes_to_hex(bytes):
    r = ""
    for b in bytes:
        r += "%02x" % b
    return r

def hex_to_base64(hex):
    return bytes_to_base64(hex_to_bytes(hex))

def base64_to_array(b64):
    r = []
    D = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    for c in b64:
        if c == '=': break
        r.append(D.index(c))
    return r 

def base64_array_to_bytes(b64_array):
    r = []
    for i in range(0, len(b64_array), 4):
        c = 0
        for j in range(4):
            if i + j >= len(b64_array):
                break
            c |= b64_array[i + j] << (18 - j * 6)
        for j in range(3):
            r.append((c >> (16 - 8 * j)) & 0xFF)
    return r

def base64_to_bytes(b64):
    return base64_array_to_bytes(base64_to_array(b64))

def base64_to_hex(b64):
    return bytes_to_hex(base64_to_bytes(b64))

def encrypt_aes_128_ecb(s, key):
    o = AES.new(key, AES.MODE_ECB)
    if len(s) % 16 != 0:
        s = pkcs7_padding(s, len(s) + 16 - len(s) % 16)
    return o.encrypt(s)

def decrypt_aes_128_ecb(s, key):
    o = AES.new(key, AES.MODE_ECB)
    return o.decrypt(s)

def hamming_distance_bytes(left_bytes, right_bytes):
    assert len(left_bytes) == len(right_bytes), "didn't write for boundary condition when len(left) != len(right)"
    # xor each byte then count bits
    z = [a ^ b for (a, b) in zip(left_bytes, right_bytes)]
    r = 0
    for b in z:
        while b > 0:
            r += b & 0x1
            b >>= 1
    return r

def hamming_distance(left, right):
    return hamming_distance_bytes([ord(c) for c in left], [ord(c) for c in right])

def pkcs7_padding_bytes(bytes, to_len):
    pad = to_len - len(bytes)
    assert pad >= 0, "byte array longer than desired pad"
    assert pad < 256, "too much padding required"

    return bytes + [pad for i in range(pad)]

def pkcs7_padding(s, to_len):
    return ''.join([chr(b) for b in pkcs7_padding_bytes([ord(c) for c in s], to_len)])

def random_aes_key_bytes():
    return [random.randint(0, 255) for i in range(16)]

def random_aes_key():
    return ''.join([chr(c) for c in random_aes_key_bytes()])

def fixed_xor_bytes(left_bytes, right_bytes):
    assert(len(left_bytes) == len(right_bytes)), "fixed_xor_bytes called with len(left) != len(right)"
    return [a ^ b for (a, b) in zip(left_bytes, right_bytes)]

def fixed_xor_hex(left, right):
    return bytes_to_hex(fixed_xor_bytes(hex_to_bytes(left), hex_to_bytes(right)))

def fixed_xor(left, right):
    return ''.join([chr(b) for b in fixed_xor_bytes([ord(c) for c in left], [ord(c) for c in right])])

def repeating_key_xor(msg, key):
    assert len(key) < len(msg), "repeating key must be shorter than message to encode"
    assert len(key) > 0, "key length > 0"
    repeating_key = ''.join([key for i in range(len(msg) / len(key))])
    repeating_key += key[:len(msg)-len(repeating_key)]
    assert len(repeating_key) == len(msg), "oops"

    return bytes_to_hex(fixed_xor_bytes([ord(c) for c in msg], [ord(c) for c in repeating_key]))

def decode_repeating_key_xor(bytes, key):
    repeating_key = ''.join([key for i in range(len(bytes) / len(key))])
    repeating_key += key[:len(bytes)-len(repeating_key)]
    assert len(repeating_key) == len(bytes), "oops"

    return ''.join([chr(b) for b in fixed_xor_bytes(bytes, [ord(c) for c in repeating_key])])

def decrypt_aes_128_cbc_bytes(bytes, key, iv):
    return [ord(c) for c in decrypt_aes_128_cbc(''.join([chr(b) for b in bytes]), key, ''.join([chr(c) for c in iv]))]

def decrypt_aes_128_cbc(s, key, iv):
    assert len(s) % 16 == 0, "s should be a multiple of 16 in length"
    r = ""
    last_block = iv
    for i in range(0, len(s), 16):
        block = s[i : i + 16]
        decrypted = decrypt_aes_128_ecb(block, key)
        decrypted = fixed_xor(last_block, decrypted)
        last_block = block
        r += decrypted
    return r

def encrypt_aes_128_cbc(s, key, iv):
    r = ""
    last_cipher = iv
    if len(s) % 16 != 0:
        s = pkcs7_padding(s, len(s) + 16 - len(s) % 16)

    for i in range(0, len(s), 16):
        block = fixed_xor(s[i : i + 16], last_cipher)
        encrypted = encrypt_aes_128_ecb(block, key)
        last_cipher = encrypted
        r += encrypted
    return r

def defeat_single_byte_xor(hex):
    return defeat_single_byte_xor_bytes(hex_to_bytes(hex))

def defeat_single_byte_xor_bytes(bytes):
    RD = "'XZYQKJVUWOLENIHDGFBTRPMCAS.zxjqkgbvpywfmculdrhsnioate " #"etaoinshrdlucmfwypvbgkqjxz"
    #RD = ".zxjqkgbvpywfmculdrhsnioate " #"etaoinshrdlucmfwypvbgkqjxz"
    MIN_NORM_SCORE = 1500 # magic number to filter out credible-to-a-machine garbage

    guesses = {}
    for guess in range(256):
        key = [guess for g in range(len(bytes))]
        r = fixed_xor_bytes(bytes, key)
        score = sum([((x < 0) and -100 or x*x) for x in [RD.find(chr(b)) for b in r]])

        # get rid of low scoring garbage
        if score/len(bytes) > MIN_NORM_SCORE:

            # make sure all scores put in guesses hash
            while guesses.has_key(score):
                score += 1

            guesses[score] = guess

    best_guess = 0
    guessed_bytes = []
    while len(guesses.keys()) > 0:
        best_guess = guesses[max(guesses.keys())]
        guessed_bytes = fixed_xor_bytes(bytes, [best_guess for g in range(len(bytes))])
        found_it = True

        for b in guessed_bytes:
            if not chr(b) in string.printable:
                del guesses[max(guesses.keys())]
                found_it = False
                break
        
        if found_it:
            break

    assert len(guesses.keys()) > 0, "Failed to guess key"

    return { 'key': best_guess,
             'decoded': ''.join([chr(b) for b in guessed_bytes]),
             'score': max(guesses.keys()),
             'norm_score': max(guesses.keys())/len(guessed_bytes) }

def defeat_repeating_key_xor(b64):
    bytes = base64_to_bytes(b64)
    KEYSIZE_MIN = 2
    KEYSIZE_MAX = 40
    KEYSIZE_BLOCKS = 4
    TRY_KEYS = 5

    keysize_guesses = {}
    key_tries = []

    for keysize in range(KEYSIZE_MIN, KEYSIZE_MAX):
        distances = []
        for i in range(0, keysize * KEYSIZE_BLOCKS, keysize):
            distances.append(hamming_distance_bytes(bytes[i:i + keysize], bytes[i + keysize:i + keysize * 2]))
        total_dist = sum(distances) / keysize
        keysize_guesses.setdefault(total_dist, []).append(keysize)

    # put top key sizes into key_tries array
    ks = keysize_guesses.keys()
    ks.sort()
    for k in ks:
        #print " -- %s: %s" %(k, keysize_guesses[k])
        for s in keysize_guesses[k]:
            key_tries.append(s)
            if len(key_tries)>TRY_KEYS:
                break

    #print key_tries

    key = []
    found_it = False
    for keysize in key_tries:
        key = []
        trans_bytes = [[] for x in range(keysize)]
        for i in range(0, len(bytes) - (len(bytes) % keysize), keysize):
            for j in range(keysize):
                trans_bytes[j].append(bytes[i + j])
        try:
            for block in trans_bytes:
                key.append(defeat_single_byte_xor_bytes(block)['key'])
            found_it = True
        except Exception, e:
            pass #print "!! %s %s" % (block, e.message)
        if found_it: break

    if not found_it:
        return {}

    key_str = ''.join([chr(b) for b in key])
    return {
        'key': key_str,
        'decoded': decode_repeating_key_xor(bytes, key_str) }

def detect_aes_128_ecb(hex):
    return detect_aes_128_ecb_bytes(hex_to_bytes(hex))

def detect_aes_128_ecb_bytes(bytes):
    BLOCK_SIZE = 16
    blocks = []
    for i in range(0, len(bytes) - (len(bytes) % BLOCK_SIZE), BLOCK_SIZE):
        blocks.append(bytes[i : i + BLOCK_SIZE])

    distances = []
    for block in blocks:
        for vs_block in blocks:
            distance = hamming_distance_bytes(block, vs_block)
            if not block is vs_block:
                distances.append(distance)

    return {
        'min': min(distances),
        'max': max(distances),
        'avg': sum(distances) / len(distances),
        'range': max(distances) - min(distances),
        'count': len(distances),
        'is_aes_128_ecb': min(distances) == 0 }

def encryption_oracle(s):
    s2 = ''.join([chr(random.randint(0, 255)) for i in range(random.randint(5, 10))]) \
         + s \
         + ''.join([chr(random.randint(0, 255)) for i in range(random.randint(5, 10))])

    if random.randint(0, 1):
        return encrypt_aes_128_ecb(s2, random_aes_key())

    else:
        return encrypt_aes_128_cbc(s2, random_aes_key(), random_aes_key())
