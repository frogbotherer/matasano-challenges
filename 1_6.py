import t

s1 = "this is a test"
s2 = "wokka wokka!!!"

print t.hamming_distance(s1, s2)

assert t.hamming_distance(s1, s2) == 37

# ======
F = open('6.txt', 'r')
a = ''.join(F.readlines()).replace('\r', '').replace('\n', '')
F.close()

print t.defeat_repeating_key_xor(a) 
