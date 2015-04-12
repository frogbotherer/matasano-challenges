import t

s = t.cbc_oracle("dummy userdata;admin=true")
assert t.is_admin(s) is False

t.defeat_cbc_bitflip()
