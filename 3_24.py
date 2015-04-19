import t

s = "this is a bit of text for encrypting as a test of prng stream ciphering with a 16-bit key."
r = t.encrypt_16bit_prng(s, 0x1234)

o = t.decrypt_16bit_prng(r, 0x1234)
print o
assert s == o

# recover key from junk+AAAA
rng = t.MTRandom()
key = rng.random(0xFFFF)
r = t.encrypt_16bit_prng(''.join([chr(rng.random(0xff)) for c in range(rng.random(10) + 5)]) + "A" * 14, key)
got_key = t.defeat_16bit_prng_stream(r, "A" * 14)

assert key == got_key
print t.decrypt_16bit_prng(r, got_key)
