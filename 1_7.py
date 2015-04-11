import t

F = open('7.txt', 'r')
a = ''.join(F.readlines()).replace('\r', '').replace('\n', '')
F.close()

s = ''.join([chr(c) for c in t.base64_to_bytes(a)])

print t.decrypt_aes_128_ecb(s, 'YELLOW SUBMARINE')
