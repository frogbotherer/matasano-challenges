import t

s = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

r = t.decrypt_aes_128_ctr(t.base64_to_str(s), "YELLOW SUBMARINE")

print r
