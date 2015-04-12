import t

valid1 = "test" + "\x0c" * 12
valid2 = "0123456789abcdef"
invalid1 = "ICE ICE BABY\x05\x05\x05\x05"
invalid2 = "ICE ICE BABY\x01\x02\x03\x04"
invalid3 = "xxxxxxxx" + "\x00" * 8

for v in (valid1, valid2):
    a = t.pkcs7_unpadding(v, 16)
    print "%s success" % a

for v in (invalid1, invalid2, invalid3):
    try:
        s = t.pkcs7_unpadding(v, 16)
    except ValueError, e:
        print e.message
    else: 
        assert False, "%s should have failed" % repr(v)
