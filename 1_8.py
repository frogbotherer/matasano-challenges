import t

F = open('8.txt', 'r')

for line in F.readlines():
    line = line.replace('\r', '').replace('\n', '')
    o = t.detect_aes_128_ecb(line)
    print "%.16s...: %s" % (line, o['is_aes_128_ecb'] and "AES-128-ECB" or "???")
F.close()

