from t import MTRandom

r = MTRandom(0)

for i in range(100):
    print "% 3d %d" % (i, r.random(100))

while r.random(100) > 0:
    pass

while r.random(100) < 99:
    pass

buckets = {}
for i in range(10):
    buckets[i] = 0

for i in range(1000):
    x = r.random(100)
    buckets[x/10] += 1

for i in range(10):
    print "%d %s" % (i, "#" * buckets[i])
