import t

#    01234567890123
s = "this is a test of ctr encryption and editing that's long enough to roll the ctr a couple of times and that."
s1 = "this is a TEST of ctr encryption and editing that's long enough to roll the ctr a couple of times and that."
k = "yellow submarine"
e = t.encrypt_aes_128_ctr(s, k)
e1 = t.edit_ctr_stream(e, 10, "TEST", k)
assert t.decrypt_aes_128_ctr(e1, k) == s1

F = open('25.txt','r')
s = ''.join(F.readlines()).replace('\r', '').replace('\n', '')
F.close()
s = t.decrypt_aes_128_ecb(t.base64_to_str(s), "YELLOW SUBMARINE")
o = t.CTRVictim(s, t.random_aes_key())

# use edit() to replace whole file with AAAA
original_cipher = o.get_ciphertext()
o.edit(0, "A" * len(original_cipher))

# xor ciphertext with AAAA to get encrypted keystream
keystream = t.fixed_xor(o.get_ciphertext(), "A" * len(original_cipher))

# xor encrypted keystream with original ciphertext to get plaintext
plaintext = t.fixed_xor(keystream, original_cipher)

print plaintext
assert plaintext == s
