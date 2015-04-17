import t

r = t.MTRandom(0)
h = t.MTHack()

for i in (0x00000000,0xFFFFFFFF,0x12345678,0x87654321,0x43214321,0x56785678):
    print " ==> %s" % hex(i)
    x = r._MTRandom__temper(i)
    print hex(x)
    print hex(h.untemper(x))

    assert h.untemper(x) == i
