import t

r = t.MTRandom(0)
h = t.MTHack()

for i in (0x00000000,0xFFFFFFFF,0x12345678,0x87654321,0x43214321,0x56785678):
    print " ==> %s" % hex(i)
    x = r._MTRandom__temper(i)
    print hex(x)
    print hex(h.untemper(x))

    assert h.untemper(x) == i

c = h.clone(r)

for i in range(10):
    a = r.extract_number()
    b = c.extract_number()
    print "%.8x %.8x" % (a, b)
    assert a == b
