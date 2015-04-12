import t

s = t.cbc_oracle("dummy userdata;admin=true")
assert t.is_admin(s) is False

r = t.defeat_cbc_bitflip()

print r

assert r
