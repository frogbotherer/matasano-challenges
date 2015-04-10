import t

r = t.pkcs7_padding("YELLOW SUBMARINE", 20)

print repr(r)

assert r == "YELLOW SUBMARINE\x04\x04\x04\x04"
