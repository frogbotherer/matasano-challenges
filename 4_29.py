import t

message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
key = t.random_aes_key()  # will do

signature = t.sha1_sign(message, key)

assert t.sha1_check_sign(message, key, signature)

new_message_suffix = ";admin=true"
x = t.defeat_sha1_signing(message, signature, new_message_suffix, lambda a, b: t.sha1_check_sign(a, key, b))
print x

(new_sig, new_message) = (x['new_sig'], x['new_message'])
r = t.sha1_check_sign(new_message, key, new_sig)
print r
assert r
