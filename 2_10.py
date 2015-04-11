import t

F = open('10.txt', 'r')
a = ''.join(F.readlines()).replace('\r', '').replace('\n', '')
F.close()

b = t.base64_to_bytes(a)

db = t.decrypt_aes_128_cbc_bytes(b, 'YELLOW SUBMARINE', [0 for i in range(16)])
print db

print ''.join([chr(b) for b in db])
