import t

F = open('20.txt', 'r')
data = F.readlines()
F.close()

key = t.random_aes_key()

r = [t.encrypt_aes_128_ctr(t.base64_to_str(d.replace('\r', '').replace('\n', '')), key) for d in data]

s = t.defeat_fixed_nonce_ctr_stats(r)

print s

print len(s)

