import t

F = open('4.txt', 'r')

for line in F.readlines():
    line = line.rstrip()
    try:
        r = t.defeat_single_byte_xor(line, detecting=True)
        print "SUCCESS: %s" % line
        print r

    except Exception, e:
        print "FAILED: %s: %s" % (line, e.message)

F.close()
