import t

assert t.md4("") == 0x31d6cfe0d16ae931b73c59d7e0c089c0, hex(t.md4(""))
assert t.md4("a") == 0xbde52cb31de33e46245e05fbdbd6fb24
assert t.md4("abc") == 0xa448017aaf21d8525fc10ae87aa6729d
assert t.md4("message digest") == 0xd9130a8164549fe818874806e1c7014b
assert t.md4("abcdefghijklmnopqrstuvwxyz") == 0xd79e1c308aa5bbcdeea8ed63df412da9
assert t.md4("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") == 0x043f8582f241db351ce627e153e7f0e4
assert t.md4("12345678901234567890123456789012345678901234567890123456789012345678901234567890") == 0xe33b4ddc9c38f2199c3e7b164fcc0536



message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
key = t.random_aes_key()  # will do

signature = t.md4_sign(message, key)

assert t.md4_check_sign(message, key, signature)

new_message_suffix = ";admin=true"
x = t.defeat_md4_signing(message, signature, new_message_suffix, lambda a, b: t.md4_check_sign(a, key, b))
print x

(new_sig, new_message) = (x['new_sig'], x['new_message'])
r = t.md4_check_sign(new_message, key, new_sig)
print r
assert r
