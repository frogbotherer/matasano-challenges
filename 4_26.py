import t

s = t.ctr_oracle("dummy userdata;admin=true")
assert t.is_admin_ctr(s) is False

r = t.defeat_ctr_bitflip()
print r
assert r
