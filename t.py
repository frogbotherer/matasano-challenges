#!/usr/bin/env python

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
    assert(len(left_bytes) == len(right_bytes))
    return [a ^ b for (a, b) in zip(left_bytes, right_bytes)]

def fixed_xor(left, right):
    return bytes_to_hex(fixed_xor_bytes(hex_to_bytes(left), hex_to_bytes(right)))

def defeat_single_byte_xor(hex):
    RD = "zxjqkgbvpywfmculdrhsnioate" #"etaoinshrdlucmfwypvbgkqjxz"
    bytes = hex_to_bytes(hex)

    guesses = {}
    for guess in range(256):
        key = [guess for g in range(len(bytes))]
        r = fixed_xor_bytes(bytes, key)
        score = sum([RD.find(chr(b)) for b in r])
        guesses[score] = guess

    best_guess = guesses[max(guesses.keys())]

    return { 'key': best_guess,
             'decoded': ''.join([chr(b) for b in fixed_xor_bytes(bytes, [best_guess for g in range(len(bytes))])]) }

