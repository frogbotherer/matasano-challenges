import t

x = t.sha1("this is a test")
print hex(x)

y = t.sha1_sign("this is a test of SHA1 signing", "a key")
assert t.sha1_check_sign("this is a test of SHA1 signing", "a key", y)

assert not t.sha1_check_sign("this IS a test of SHA1 signing", "a key", y)

assert t.sha1_sign("test", "key1") != t.sha1_sign("test", "key2")
