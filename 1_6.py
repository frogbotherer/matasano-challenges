import t

s1 = "this is a test"
s2 = "wokka wokka!!!"

print t.hamming_distance(s1, s2)

assert t.hamming_distance(s1, s2) == 37
