import t
import time

sleep_r = t.MTRandom(int(time.time())) # for sleeping a random time(!)
time.sleep(sleep_r.random(60) + 40) # 40 and 100 :P

secret_seed = int(time.time())
r = t.MTRandom(secret_seed)
first_num = r.extract_number()
time.sleep(sleep_r.random(60) + 40) # 40 and 100 :P

h = t.MTHack()
seed = h.get_seed_from_recent_unix_timestamp(first_num)
print "%x == %x ?" % (seed, secret_seed)
assert seed == secret_seed
