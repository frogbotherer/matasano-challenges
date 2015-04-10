import t
from Crypto.Cipher import AES

F = open('7.txt', 'r')
a = ''.join(F.readlines()).replace('\r', '').replace('\n', '')
F.close()

s = ''.join([chr(c) for c in t.base64_to_bytes(a)])

o = AES.new('YELLOW SUBMARINE', AES.MODE_ECB)
print o.decrypt(s)
