import requests, hashlib, base64

URL = "http://localhost:5000"

class Client(object):
    def __init__(self, url):
        self.url = url

        self.pub = None
        self.priv = None

    def register(self):
        a, q = self.pow()

        if a == -1:
            raise Exception("Failed to prove work!")

        r = requests.post(self.url + "/api/register", params={
            "powq": q,
            "powa": a,
            "username": "test"
        })
        data = r.json()
        print data
        r.raise_for_status()
        return data["keys"]['private'], data["keys"]['public']

    def login(self):
        a, q = self.pow()

        if a == -1:
            raise Exception("Failed to prove work!")

    def pow(self):
        r = requests.get(self.url + "/api/hash")
        r.raise_for_status()
        r = r.json()

        base = base64.b64decode(r["base"])
        guess = 0
        while guess < r["load"]:
            if hashlib.sha512(str(guess) + base).hexdigest() == r["hash"]:
                return (guess, r["base"])
            guess += 1

        return (-1, "")

c = Client(URL)
# print c.register()

# start = time.time()

# print r
# print run_pow(str(r["hash"]), str(r["base"]), r["load"])
# print "Took %s" % (time.time() - start)
