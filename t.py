#!/usr/bin/env python

import string  # for printable
import random  # for randint
import time    # for time.time()
import sys     # for sys.stdout.flush/write
from Crypto.Cipher import AES  # pip install PyCrypto

def bytes_to_base64_array(bytes_in):
    r = []
    bytes = [b for b in bytes_in]
    while len(bytes) % 3 != 0:
        bytes.append(0)

    for i in range(0, len(bytes), 3):
       # c is a 24bit representation of three input bytes
       c = 0
       for j in range(3):
          c += bytes[i + j] << (16 - 8 * j)
       for j in range(4):
          if i + j > len(bytes_in):
              r.append(0x40)
          else:
              r.append(0x3F & (c >> (18 - 6 * j)))
    return r

def base64_array_to_base64(b64_array):
    r = ""
    D = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
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

def str_to_hex(s):
    return ''.join(["%02x" % ord(r) for r in s])

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
    expected_len = int(len(b64_array) * 3 / 4)
    for i in range(0, len(b64_array), 4):
        c = 0
        for j in range(4):
            if i + j >= len(b64_array):
                break
            c |= b64_array[i + j] << (18 - j * 6)
        for j in range(3):
            if len(r) >= expected_len:
                break
            r.append((c >> (16 - 8 * j)) & 0xFF)
    return r

def base64_to_bytes(b64):
    return base64_array_to_bytes(base64_to_array(b64))

def base64_to_hex(b64):
    return bytes_to_hex(base64_to_bytes(b64))

def base64_to_str(b64):
    return ''.join([chr(b) for b in base64_to_bytes(b64)])

def encrypt_aes_128_ecb(s, key):
    o = AES.new(key, AES.MODE_ECB)
    if len(s) % 16 != 0:
        s = pkcs7_padding(s, len(s) + 16 - len(s) % 16)
    return o.encrypt(s)

def decrypt_aes_128_ecb(s, key, unpad=True):
    o = AES.new(key, AES.MODE_ECB)
    if unpad:
        return pkcs7_unpadding(o.decrypt(s), 16)
    else:
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
    # "If the original data is a multiple of N bytes, then an extra block of bytes with value N is added."
    pad = to_len - len(bytes)
    if pad == 0:
        pad = to_len
    assert pad >= 0, "byte array longer than desired pad"
    assert pad < 256, "too much padding required"

    return bytes + [pad for i in range(pad)]

def pkcs7_padding(s, to_len):
    return ''.join([chr(b) for b in pkcs7_padding_bytes([ord(c) for c in s], to_len)])

def pkcs7_unpadding_bytes(bytes, block_size):
    if bytes[-1] == 0:
        raise ValueError, "Invalid pkcs7 padding: last byte is 0x0"
    if bytes[-1 * bytes[-1]:] != [bytes[-1] for b in range(bytes[-1])]:
        raise ValueError, "Invalid pkcs7 padding: last byte is %d but trailing bytes are %s" % (bytes[-1], bytes[-1 * bytes[-1]:])
    return bytes[:-1 * bytes[-1]]

def pkcs7_unpadding(s, block_size):
    return ''.join([chr(b) for b in pkcs7_unpadding_bytes([ord(c) for c in s], block_size)])

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

def decrypt_aes_128_cbc(s, key, iv, use_strict_pkcs7=False):
    assert len(s) % 16 == 0, "s should be a multiple of 16 in length"
    r = ""
    last_block = iv
    for i in range(0, len(s), 16):
        block = s[i : i + 16]
        decrypted = decrypt_aes_128_ecb(block, key, unpad=False)
        decrypted = fixed_xor(last_block, decrypted)
        if i == len(s) - 16 and (use_strict_pkcs7 or ord(decrypted[-1]) <= 16):
            decrypted = pkcs7_unpadding(decrypted, 16)
        last_block = block
        r += decrypted
    return r

def encrypt_aes_128_cbc(s, key, iv):
    r = ""
    last_cipher = iv
    # if s ends on a block boundary, add a whole block of padding
    s = pkcs7_padding(s, len(s) + 16 - len(s) % 16)

    for i in range(0, len(s), 16):
        block = fixed_xor(s[i : i + 16], last_cipher)
        encrypted = encrypt_aes_128_ecb(block, key)
        last_cipher = encrypted
        r += encrypted
    return r

def decrypt_aes_128_ctr(s, key, nonce=chr(0) * 8, offset=0):
    block_size = 16
    r = ""
    for i in range(0, len(s), block_size):
        ctr = int(i / block_size) + offset
        ctr_li = ""
        for b in range(0, 64, 8):
            ctr_li += chr(0xff & (ctr >> b))
        keystream = encrypt_aes_128_ecb(nonce[::-1] + ctr_li, key)

        if i + block_size > len(s):
            # last block doesn't align to boundary
            r += fixed_xor(s[i:], keystream[: len(s) % block_size])
        else:
            r += fixed_xor(s[i : i + block_size], keystream)
    return r

def encrypt_aes_128_ctr(s, key, nonce=chr(0) * 8, offset=0):
    return decrypt_aes_128_ctr(s, key, nonce, offset)

def edit_ctr_stream(ciphertext, offset, newtext, key, nonce=chr(0) * 8):
    block_size = 16
    first_block_start = int(offset / block_size) * block_size
    first_block_offset = offset % block_size
    last_block_start = int((offset + len(newtext)) / block_size) * block_size
    last_block_end = block_size - (offset + len(newtext)) % block_size

    decrypted_orig = decrypt_aes_128_ctr(ciphertext[first_block_start : last_block_start + block_size], key, nonce, first_block_start / block_size)
    decrypted = decrypted_orig[:first_block_offset] + newtext
    if last_block_end < block_size and last_block_start + block_size < len(ciphertext):
        # don't add the same block again if it ends on a boundary; don't forget CTR doesn't align to block size
        decrypted += decrypted_orig[-1 * last_block_end:]
    encrypted = encrypt_aes_128_ctr(decrypted, key, nonce, first_block_start / block_size)

    return ciphertext[:first_block_start] + encrypted + ciphertext[last_block_start + block_size:]

def encrypt_16bit_prng(s, seed):
    rng = MTRandom(seed & 0xFFFF)
    ## i think this makes the problem impossible to solve because we're trashing 3/4 of the returned prn
    ## ... and that means you can't untemper the prng output
    #keystream = ''.join([chr(rng.extract_number() & 0xFF) for c in s])
    keystream = ""
    prn_bytes_remaining = 0
    prn = 0
    for c in s:
        if prn_bytes_remaining == 0:
            prn = rng.extract_number()
            prn_bytes_remaining = 3
        else:
            prn = prn >> 8
            prn_bytes_remaining -= 1
        keystream += chr(prn & 0xFF)

    return fixed_xor(s, keystream)

def decrypt_16bit_prng(s, seed):
    return encrypt_16bit_prng(s, seed) # lolz

class MTRandom:
    def __init__(self, seed=int(time.time())):
        self.__MT = [0 for i in range(624)]
        self.__index = 0
        self.initialise_generator(seed)

    def initialise_generator(self, seed):
        self.__index = 0
        self.__MT[0] = seed
        for i in range(1, 624):
            self.__MT[i] = 0xFFFFFFFF & (0x6C078965 * (self.__MT[i - 1] ^ (self.__MT[i - 1] >> 30)) + i)

    def extract_number(self):
        if self.__index == 0:
            self.generate_numbers()

        y = self.__MT[self.__index]
        self.__index = (self.__index + 1) % 624

        return self.__temper(y)

    def __temper(self, y):
        y = y ^ (y >> 11)
        y = y ^ ((y << 7) & 0x9D2C5680)
        y = y ^ ((y << 15) & 0xEFC60000)
        y = y ^ (y >> 18)
        return y
       
    def generate_numbers(self):
        for i in range(624):
            y = (self.__MT[i] & 0x80000000) + (self.__MT[(i + 1) % 624] & 0x7FFFFFFF)
            self.__MT[i] = self.__MT[(i + 397) % 624] ^ (y >> 1)
            if y % 2 != 0:
                self.__MT[i] = self.__MT[i] ^ 0x9908B0DF

    def random(self, base):
        return int(base * self.extract_number() / (1 << 32))

    def set_state(self, MT):
        assert len(MT) == 624
        self.__MT = MT

    def get_state(self):
        return self.__MT

class MTHack:

    def __init__(self):
        self.__MT = [0 for i in range(624)]
        self.__index = 0

    def untemper(self, y):
        y = y ^ (y >> 18)

        y = y ^ ((y << 15) & 0xEFC60000)

        # temper:
        #   84218421 84218421 84218421 84218421
        #   00010010 00110100 01010110 01111000  # 0x12345678
        #   00011010 00101011 00111100 0         # << 7
        #   10011100 00101100 01010110 10000000  # 0x9D2C5680
        #   00011000 00101000 00010100 0         # &
        #   00001010 00011100 01000010 01111000  # xor (1)
        #      0   a    1   c    4   2    7   8
        # untemper:
        #                               1111000  # these are same as before  # y
        #                       010100 0         # << 7, & 0x9D2C5680
        #                       010110 0         # ... and xor with (1)      # y1
        #               01000 00                 # << 7 these & 0x9D2C5680
        #               10100 01                 # ... and xor (1) again     # y2
        #       1000 001                         # << 7, &
        #       0010 001                         # ... xor
        # ... ad infinitum
        mask = 0x7f
        r = y & mask
        for i in range(7, 32, 7):
            mask <<= 7
            r |= ((0x9D2C5680 & (r << 7)) ^ y) & mask
        y = r & 0xffffffff

        # temper:
        #   84218421 84218421 84218421 84218421
        #   00010010 00110100 01010110 01111000  # 0x12345678
        #               00010 01000110 10001010  # >> 11
        #   00010010 00110110 00010000 11110010  # xor (1)
        # untemper:
        #   00010010 001                         # these are same as before  # y
        #               00010 010001             # same bits >> 11
        #               10110 000100             # ... and xor with (1)
        #               10100 010101             # ... gives next 11 bits    # y1
        #                           10 10001010  # these bits >> 11 again
        #                           10 01111000  # ... xor with(1) again
        #   00010010 00110100 01010110 01111000  # gives final result!
        y1 = y ^ (y >> 11)
        y = y ^ (y1 >> 11)

        return y

    def ungenerate_numbers(self):
        ## reverse this
        #for i in range(624):
        #    y = (self.__MT[i] & 0x80000000) + (self.__MT[(i + 1) % 624] & 0x7FFFFFFF)
        #    self.__MT[i] = self.__MT[(i + 397) % 624] ^ (y >> 1)
        #    if y % 2 != 0:
        #        self.__MT[i] = self.__MT[i] ^ 0x9908B0DF
        pass

    def uninitialise(self):
        ## reverse this
        #self.__MT[0] = seed
        #for i in range(1, 624):
        #    self.__MT[i] = 0xFFFFFFFF & (0x6C078965 * (self.__MT[i - 1] ^ (self.__MT[i - 1] >> 30)) + i)
        pass

    def get_seed_from_recent_unix_timestamp(self, num, recent=2 * 60 * 60):
        ## for 0th register, we need to reverse:
        #self.__MT[0] = seed
        #for i in range(1, 398):
        #    self.__MT[i] = 0xFFFFFFFF & (0x6C078965 * (self.__MT[i - 1] ^ (self.__MT[i - 1] >> 30)) + i)
        #y = (self.__MT[0] & 0x80000000) + (self.__MT[1] & 0x7FFFFFFF)
        #self.__MT[0] = self.__MT[397] ^ (y >> 1)
        #if y % 2 != 0:
        #    self.__MT[0] = self.__MT[0] ^ 0x9908B0DF

        ## some assumptions
        ##  * recent == last 2 hours
        ##  * clock on prng host might be out by a few seconds
        ##  * seeded with 32bit seconds since epoch (i.e. int(time.time()))

        ## approach:
        ##  * untemper num
        ##  * iterate through 2h-worth of timestamps until we get a match
        untempered_num = self.untemper(num)
        now = int(time.time()) + 60  # out by up to a minute
        for seed in range(now - recent, now):
            self.__MT[0] = seed
            for i in range(1, 398):
                self.__MT[i] = 0xFFFFFFFF & (0x6C078965 * (self.__MT[i - 1] ^ (self.__MT[i - 1] >> 30)) + i)
            y = (self.__MT[0] & 0x80000000) + (self.__MT[1] & 0x7FFFFFFF)
            self.__MT[0] = self.__MT[397] ^ (y >> 1)
            if y % 2 != 0:
                self.__MT[0] = self.__MT[0] ^ 0x9908B0DF
            if self.__MT[0] == untempered_num:
                return seed
        raise ValueError, "couldn't calculate seed from %d in last %d seconds" % (num, recent)

    def clone(self, rng):
        assert isinstance(rng, MTRandom), "can only clone MTRandom instances"

        clone_rng = MTRandom()
        clone_MT = []

        for i in range(624):
            clone_MT.append(self.untemper(rng.extract_number()))

        clone_rng.set_state(clone_MT)
        return clone_rng

    def get_seed_from_16bit_prng(self, offset, nums):
        untempered = [self.untemper(n) for n in nums]
        call_count = offset + len(nums)
        assert call_count < 624, "didn't code for registers wrapping"

        # brute force seed, calculating as little as possible to keep loop tight
        for seed in range(1 << 16):
            if seed % (1 << 10) == 0:
                sys.stdout.write("%d%%\r" % int(seed * 100 / (1 << 16)))
                sys.stdout.flush()

            self.__MT[0] = seed
            for i in range(1, 397 + call_count):
                self.__MT[i] = 0xFFFFFFFF & (0x6C078965 * (self.__MT[i - 1] ^ (self.__MT[i - 1] >> 30)) + i)

            for i in range(call_count):
                y = (self.__MT[i] & 0x80000000) + (self.__MT[i + 1] & 0x7FFFFFFF)
                self.__MT[i] = self.__MT[(i + 397) % 624] ^ (y >> 1)
                if y % 2 != 0:
                    self.__MT[i] = self.__MT[i] ^ 0x9908B0DF

            if untempered == self.__MT[offset:call_count]:
                sys.stdout.write('\n')
                sys.stdout.flush()
                return seed

        assert False, "couldn't find seed for %s, offset %d" % ([hex(n) for n in nums], offset)


def defeat_single_byte_xor(hex, detecting=False):
    return defeat_single_byte_xor_bytes(hex_to_bytes(hex), detecting)

def defeat_single_byte_xor_bytes(bytes, detecting=False):
    RD = "\n'XZYQKJVUWOLENIHDGFBTRPMCAS.zxjqkgbvpywfmculdrhsnioate " #"etaoinshrdlucmfwypvbgkqjxz"
    #RD = ".zxjqkgbvpywfmculdrhsnioate " #"etaoinshrdlucmfwypvbgkqjxz"
    MIN_NORM_SCORE = 1000 # magic number to filter out credible-to-a-machine garbage
    guesses = {}
    for guess in range(256):
        key = [guess for g in range(len(bytes))]
        r = fixed_xor_bytes(bytes, key)
        score = 0
        is_printable = True
        for b in r:
            if not chr(b) in string.printable:
                score = -1000000
                is_printable = False
                break
            s = RD.find(chr(b))
            if s == -1:
                score -= 10000
            else:
               score += s * s

        if is_printable:
            score /= len(bytes)

            # make sure all scores put in guesses hash
            while guesses.has_key(score):
                score += 1

            guesses[score] = guess

    if len(guesses.keys()) == 0:
        raise ValueError, "No good guesses for key"

    if detecting and max(guesses.keys()) < MIN_NORM_SCORE:
        raise ValueError, "Probably not valid single byte xor"

    best_guess = guesses[max(guesses.keys())]
    guessed_bytes = fixed_xor_bytes(bytes, [best_guess for g in range(len(bytes))])

    return { 'key': best_guess,
             'decoded': ''.join([chr(b) for b in guessed_bytes]),
             'score': max(guesses.keys()),
             'norm_score': max(guesses.keys())/len(guessed_bytes) }

def defeat_repeating_key_xor(b64, fix_keysize=0):
    return defeat_repeating_key_xor_bytes(base64_to_bytes(b64), fix_keysize)

def defeat_repeating_key_xor_bytes(bytes, fix_keysize=0):
    KEYSIZE_MIN = 2
    KEYSIZE_MAX = 40
    KEYSIZE_BLOCKS = 4
    TRY_KEYS = 5

    keysize_guesses = {}
    key_tries = []

    if fix_keysize == 0:
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
            for s in keysize_guesses[k]:
                key_tries.append(s)
                if len(key_tries)>TRY_KEYS:
                    break
    else:
        key_tries = [fix_keysize]

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
                #print "OK %s" % block
            found_it = True
        except ValueError, e:
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

def is_ecb_or_cbc():
    q = encryption_oracle("A" * 64)
    a = detect_aes_128_ecb_bytes([ord(c) for c in q])

    return "%s is %s" % (str_to_hex(q), a['is_aes_128_ecb'] and "ECB" or "CBC")

ECB_ORACLE_FIXED_KEY = random_aes_key()
def encryption_oracle_ecb_fixed_key(s, secret):
    return encrypt_aes_128_ecb(s + secret, ECB_ORACLE_FIXED_KEY)

ECB_ORACLE_LEADING_JUNK = ''.join([chr(random.randint(0, 255)) for i in range(random.randint(5, 50))])
def encryption_oracle_ecb_fixed_key_leading_junk(s, secret):
    return encrypt_aes_128_ecb(ECB_ORACLE_LEADING_JUNK + s + secret, ECB_ORACLE_FIXED_KEY)

def defeat_ecb_fixed_key_with_oracle(secret, oracle=encryption_oracle_ecb_fixed_key):
    # get block size
    cipher_size = len(oracle("A", secret))
    next_cipher_size = cipher_size
    attempt = "A"
    while cipher_size == next_cipher_size:
        attempt += "A"
        next_cipher_size = len(oracle(attempt, secret))
    block_size = next_cipher_size - cipher_size

    # detect ecb
    assert detect_aes_128_ecb_bytes([ord(c) for c in oracle("A" * block_size * 4, secret)])['is_aes_128_ecb'], "oops not ecb"

    # calculate size of leading junk (if any)
    o = oracle("A" * block_size * 4, secret)
    #  - find out encrypted version of all As block
    all_as_block = ""
    for i in range(0, len(o), block_size):
        if o[i : i + block_size] == o[i + block_size : i + block_size * 2]:
            all_as_block = o[i : i + block_size]
            break

    #  - decrement number of As until one all As block disappears
    a_count = block_size * 2  # guarantees a block of all As
    while oracle("A" * a_count, secret).find(all_as_block) > -1:
        a_count -= 1
    a_count += 1
    #  - this number mod 16 is number of As that trail junk before block boundary
    #  - junk occupies all blocks before all As, minus number above
    junk_length = oracle("A" * a_count, secret).find(all_as_block) - a_count % block_size

    # break ecb
    bodge_block = "A" * ((cipher_size - junk_length) - 1)
    block_offset = cipher_size - block_size

    r = ""
    for i in range(cipher_size):
        encrypted_block = oracle(bodge_block, secret)[block_offset : block_offset + block_size]

        # assume encrypted value is printable
        for c in string.printable:
            try_block = oracle(bodge_block + r + c, secret)[block_offset : block_offset + block_size]
            if try_block == encrypted_block:
                r += c
                bodge_block = bodge_block[1:]
                break

    return r

def parse_kv(s):
    r = {}
    for (k, v) in [x.split('=') for x in s.split('&')]:
        r[k] = v
    return r

def profile_for(email):
    return "email=%s&uid=%d&role=user" % (email.replace('&', '%26').replace('=', '%3d'), 10)

def defeat_ecb_mitm(email, mitm_cb=lambda a, o: a):
    key = random_aes_key()

    # prep oracle
    oracle = lambda x: encrypt_aes_128_ecb(profile_for(x), key)
    
    # encrypt profile
    s = oracle(email)

    # provide to attacker
    s = mitm_cb(s, oracle)

    # decrypt profile
    return parse_kv(decrypt_aes_128_ecb(s, key))

def ecb_mitm(s, oracle):
    # supply e-mail address of As, then "admin" + pkcs7 padding, such that "a" of "admin" is aligned with block start
    #0123456789abcdef0123456789abcdef
    #email=AAAAAAAAAAadmin-----------
    admin_block = oracle(("A" * 10) + pkcs7_padding("admin", 16))[16:32]
    # supply e-mail address that puts = of role= at end of block and get encrypted string
    #0123456789abcdef0123456789abcdef0123456789abcdef
    #email=AAAAAAAAAAAAA&uid=10&role=
    #r = oracle("A" * 13)  ## or how about an e-mail addr to a domain that we control
    r = oracle("AAAA@evil.com")
    # substitute last block with encrypted "admin" block
    r = r[:32] + admin_block
    # return result
    return r

CBC_ORACLE_KEY = random_aes_key()
CBC_ORACLE_IV = random_aes_key()
def cbc_oracle(userdata):
    s = "comment1=cooking%20MCs;userdata=" \
        + userdata.replace(';', '%3b').replace('=', '%3d') \
        + ";comment2=%20like%20a%20pound%20of%20bacon"
    return encrypt_aes_128_cbc(s, CBC_ORACLE_KEY, CBC_ORACLE_IV)

def ctr_oracle(userdata):
    s = "comment1=cooking%20MCs;userdata=" \
        + userdata.replace(';', '%3b').replace('=', '%3d') \
        + ";comment2=%20like%20a%20pound%20of%20bacon"
    return encrypt_aes_128_ctr(s, CBC_ORACLE_KEY, CBC_ORACLE_IV[:8])

def encrypt_random_cbc(strings, iv):
    return encrypt_aes_128_cbc(random.choice(strings), CBC_ORACLE_KEY, iv)

def check_cbc_padding(s, iv):
    m = ""
    try:
        m = decrypt_aes_128_cbc(s, CBC_ORACLE_KEY, iv, use_strict_pkcs7=True)
    except ValueError, e:
        return False
    return True

def is_admin(s):
    decrypted = decrypt_aes_128_cbc(s, CBC_ORACLE_KEY, CBC_ORACLE_IV)
    return "admin=true" in decrypted.split(';')

def is_admin_ctr(s):
    decrypted = decrypt_aes_128_ctr(s, CBC_ORACLE_KEY, CBC_ORACLE_IV[:8])
    return "admin=true" in decrypted.split(';')

def flip_bit(byte, bit):
    # bit 0 = lsb
    return (byte ^ (1 << bit)) | (byte & (0xFF - (1 << bit)))

def flip_bit_chr(c, bit):
    return chr(flip_bit(ord(c), bit))

def defeat_ctr_bitflip():
    # find a block boundary after prefix
    #  - find right amount of As to get to end of block (i think i need to guess this too :()
    block_size = 16
    first_block_end = ""

    #  - find how many prefix blocks (i think you need to guess this :()
    prefix_offset = block_size * 3  # 32 chars for prefix, plus 16 for AAAAs

    # both of these values (prefix_offset and first_block_end) are evident from the unencrypted prefix,
    # but we could do a nested for-loop to guess them without too much bother -- there's only about 80
    # bytes in the whole cipher

    # supply some padding, plus :admin<true (i.e. LSBs flipped from ; and =)
    # (i've left padding == block_size, like with CBC, but i don't think it's needed here)
    # send to oracle
    s = ctr_oracle(first_block_end + ("A" * block_size) + ":admin<true")

    # flip LSB in bytes 1 and 7 of the :admin<true ciphertext (wtf?!?)
    s = s[:prefix_offset] \
        + flip_bit_chr(s[prefix_offset], 0) \
        + s[prefix_offset + 1 : prefix_offset + 6] \
        + flip_bit_chr(s[prefix_offset + 6], 0) \
        + s[prefix_offset + 7:]

    # pass back to is_admin
    r = is_admin_ctr(s)

    assert r, "oops"
    return r

def defeat_cbc_bitflip():
    # find a block boundary after prefix
    #  - find right amount of As to get to end of block (i think i need to guess this too :()
    block_size = 16
    first_block_end = ""

    #  - find how many prefix blocks (i think you need to guess this :()
    prefix_offset = block_size * 2

    # both of these values (prefix_offset and first_block_end) are evident from the unencrypted prefix,
    # but we could do a nested for-loop to guess them without too much bother -- there's only about 80
    # bytes in the whole cipher

    # supply a block of sacrificial As
    # supply a block containing :admin<true (i.e. LSBs flipped from ; and =)
    # send to oracle
    s = oracle(first_block_end + ("A" * block_size) + ":admin<true")

    # flip LSB in bytes 1 and 7 of sacrificial block
    s = s[:prefix_offset] \
        + flip_bit_chr(s[prefix_offset], 0) \
        + s[prefix_offset + 1 : prefix_offset + 6] \
        + flip_bit_chr(s[prefix_offset + 6], 0) \
        + s[prefix_offset + 7:]

    # pass back to is_admin
    r = is_admin(s)
    assert r, "oops"
    return r

def defeat_cbc_padding_oracle(s, iv):
    r = ""
    block_size = 16
    s = iv + s
    for i in range(len(s) - block_size * 2, -1, -1 * block_size):
        tamper_chunk = s[i : i + block_size]
        intermediate_chunk = ""
        padding_chunk = ""
        scan_from_byte = 0
        j = block_size - 1
        while j >= 0:  # while rather than for because we need to reset the counter
            padding_byte = block_size - j
            for b in range(scan_from_byte, 256):
                new_chunk = tamper_chunk[:j] + chr(b) + padding_chunk
                try_s = s[:i] + new_chunk + s[i + block_size : i + block_size * 2]

                if check_cbc_padding(try_s, iv):
                    intermediate_chunk = chr(b ^ padding_byte) + intermediate_chunk
                    scan_from_byte = 0
                    #print "%d found: %s %s" % (j, new_chunk, intermediate_chunk)
                    #padding_chunk =  # must decrypt to 0x2, then [0x3,0x3], ... [padding_byte+1] * padding_byte
                    padding_chunk = fixed_xor(intermediate_chunk, chr(padding_byte + 1) * padding_byte)
                    j -= 1
                    break

                if b == 255:
                    # the previous intermediate byte is wrong, go back and try again!
                    padding_byte -= 1
                    j += 1
                    scan_from_byte = (ord(intermediate_chunk[0]) ^ padding_byte) + 1
                    intermediate_chunk = intermediate_chunk[1:]
                    padding_chunk = padding_chunk[1:]
                    #print "%d reset: %s %d %d" % (j-1, intermediate_chunk, padding_byte, scan_from_byte)

        r = fixed_xor(s[i : i + block_size], intermediate_chunk) + r
    return pkcs7_unpadding(r, block_size)

def defeat_fixed_nonce_ctr(data):
    # why don't i just take the nth block of each and treat as 40 blocks of repeating key xor ? ...
    # why don't i try to find the longest keystream in the set of data, then use that to decrypt all the messages ? ...
    block_size = 16
    max_data_len = max([len(d) for d in data])
    r = ["" for i in range(len(data))]
    keystream = ""
    for i in range(0, max_data_len, block_size):
        nth_block_bytes = []
        for d in data:
            block = d[i : i + block_size]
            if len(block) < block_size:
                # pad with nulls to end of block?!?
                nth_block_bytes.extend([ord(c) for c in block] + [0 for b in range(block_size - len(block))]) 
            else:
                nth_block_bytes.extend([ord(c) for c in block])

        s = defeat_repeating_key_xor_bytes(nth_block_bytes, block_size)
        if s.has_key('decoded'):
            for j in range(0, len(s['decoded']), block_size):
                r[j/block_size] += s['decoded'][j : j + block_size] 
            if i >= len(keystream):
                keystream += s['key']
    print repr(keystream)
    print len(keystream)
    return r

def defeat_fixed_nonce_ctr_stats(data):
    min_cipher_len = min([len(d) for d in data])
    cipher_all = ""
    for d in data:
        cipher_all += d[:min_cipher_len]
    s = defeat_repeating_key_xor_bytes([ord(c) for c in cipher_all], min_cipher_len)
    r = []
    for i in range(0, len(s['decoded']), min_cipher_len):
        r.append(s['decoded'][i:i + min_cipher_len])

    return r

def defeat_16bit_prng_stream(s, predictable_s):
    # s is encrypted, with predictable_s at the end of it
    # assumptions:
    #   * s is encrypted lsb first with all four bytes from MT in keystream
    #   * MT prng started at index 0 with first byte
    #   * MT prng has 16bit seed (other bits 0)
    #   * number of encrypted bytes < 624
    h = MTHack()

    # work out how many calls to prng before s gets predictable
    # figure out how many bytes of encrypted string to skip *and* how many bytes of
    # the predictable string to skip because they weren't aligned to a 32-bit boundary
    offset = len(s) - len(predictable_s)
    offset_predictable = 4 - (offset % 4)
    offset += offset_predictable
    # work out prng output values
    n = []
    for i in range(0, len(predictable_s) - offset_predictable, 4):
        # i.e. start at the 32-bit boundary and increment in 4 byte words
        if i + 4 > len(predictable_s) - offset_predictable:
            break
        n.append(0)
        for j in range(4):
            c = ord(s[offset + i + j])
            p = ord(predictable_s[i + j])
            n[-1] |= (c ^ p) << (j * 8)

    return h.get_seed_from_16bit_prng(offset / 4, n)

def random_password_token():
    rng = MTRandom(int(time.time()))
    c = rng.extract_number()
    b = []
    for i in range(4):
        b.append((c >> ((3 - i) * 8)) & 0xFF)

    return bytes_to_base64(b)

def is_random_password_token(token):
    h = MTHack()
    b = base64_to_bytes(token)
    assert len(b) == 4
    c = 0
    for i in range(len(b)):
        c |= b[i] << ((len(b) - i - 1) * 8)

    try:
        seed = h.get_seed_from_recent_unix_timestamp(c)
        return True
    except ValueError, e:
        return False

class CTRVictim:
    def __init__(self, s, key, nonce=chr(0) * 8):
        self.__key = key
        self.__nonce = nonce
        self.__ciphertext = encrypt_aes_128_ctr(s, key, nonce)

    def get_ciphertext(self):
        return self.__ciphertext

    def edit(self, offset, text):
        self.__ciphertext = edit_ctr_stream(self.__ciphertext, offset, text, self.__key, self.__nonce)
