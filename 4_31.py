import t

with open('10.txt') as f:
    print "%x" % t.hmac(f.read(), "test")

app = t.get_file_app()

app.run()
