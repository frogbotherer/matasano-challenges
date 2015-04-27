import t

message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
key = t.random_aes_key()  # will do

signature = t.sha1_sign(message, key)

assert t.sha1_check_sign(message, key, signature)

new_message_suffix = ";admin=true"
(new_sig, new_message) = t.defeat_sha1_signing(message, signature, new_message_suffix)

print "#"*80
t.sha1(key + message + t.md_padding(key+message) + new_message_suffix)
print "#"*80
r = t.sha1_check_sign(new_message, key, new_sig)
print r
assert r
