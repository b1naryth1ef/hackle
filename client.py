import requests, hashlib, base64, time, json

import nacl.utils
from nacl.public import PrivateKey, Box, PublicKey
from nacl.encoding import Base64Encoder

URL = "http://localhost:5000"

class Client(object):
    def __init__(self, url):
        self.url = url

        self.uid = None
        self.client_key = None
        self.server_key = None

        self.public_key = None
        self.private_key = None

    def register(self):
        a, q = self.pow()

        if a == -1:
            raise Exception("Failed to prove work!")

        r = requests.post(self.url + "/api/register", params={
            "powq": q,
            "powa": a
        })
        try:
            r.raise_for_status()
        except:
            print r.content
            raise

        resp = r.json()
        self.private_key = base64.b64decode(resp["privkey"])
        self.public_key = base64.b64decode(resp["pubkey"])
        self.client_key = PrivateKey(self.private_key[:32])
        self.uid = resp["uid"]

    def login(self, uid):
        a, q = self.pow()

        if a == -1:
            raise Exception("Failed to prove work!")

        if not self.server_key or not self.client_key:
            raise Exception("Must have keys set to login!")

        payload = json.dumps({
            "timestamp": time.time(),
        })

        box = Box(self.client_key, self.server_key)
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        payload = box.encrypt(payload, nonce)

        r = requests.post(self.url + "/api/login", params={
            "powa": a,
            "powq": q,
            "payload": base64.b64encode(payload),
            "uid": uid
        })

        try:
            r.raise_for_status()
        except:
            print r.content
            raise

        print r.json()

    def info(self):
        r = requests.get(self.url + "/api/info")
        self.server_key = PublicKey(r.json()["key"], Base64Encoder)

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
c.info()

c.register()
c.login(c.uid)
