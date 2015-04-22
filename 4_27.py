import t

s = t.cbc_oracle("dummy userdata;admin=true", True)
assert t.is_admin(s, True) is False

t.defeat_cbc_with_iv_eq_key()

