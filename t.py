#!/usr/bin/env python

import string

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
        r += "%x" % (b)
    return r

def hex_to_base64(hex):
    return bytes_to_base64(hex_to_bytes(hex))

def fixed_xor_bytes(left_bytes, right_bytes):
    assert(len(left_bytes) == len(right_bytes)), "fixed_xor_bytes called with len(left) != len(right)"
    return [a ^ b for (a, b) in zip(left_bytes, right_bytes)]

def fixed_xor(left, right):
    return bytes_to_hex(fixed_xor_bytes(hex_to_bytes(left), hex_to_bytes(right)))

def defeat_single_byte_xor(hex):
    RD = "'XZYQKJVUWOLENIHDGFBTRPMCAS.zxjqkgbvpywfmculdrhsnioate " #"etaoinshrdlucmfwypvbgkqjxz"
    #RD = ".zxjqkgbvpywfmculdrhsnioate " #"etaoinshrdlucmfwypvbgkqjxz"
    MIN_NORM_SCORE = 1500 # magic number to filter out credible-to-a-machine garbage
    bytes = hex_to_bytes(hex)

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

