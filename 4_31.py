import t

with open('10.txt') as f:
    print "%x" % t.hmac(f.read(), "test")

app = t.get_file_app()
print app.request("/test?file=10.txt&signature=a4d4bcbb415a9f68103ff55138a7754c1cc9d31b").status

f = '10.txt'
sig = t.defeat_hmac_timing(app, f)
r =  app.request("/test?file=%s&signature=%s" % (f, sig))
print "%s\n%s" % (r.status, r.data)

assert r.status == '200 OK'
