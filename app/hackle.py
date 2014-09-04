import json, time, hashlib, random, os, base64
from klein import route
from twisted.internet import defer
from twisted.enterprise import adbapi
from twisted.internet import protocol
from twisted.internet import reactor
import botan, txredis

dbpool = adbapi.ConnectionPool("sqlite3", "hek.db", check_same_thread=False)
rng = botan.RandomNumberGenerator()
clientCreator = protocol.ClientCreator(reactor, txredis.HiRedisClient)

REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS = None

PUBKEY = None
PRIVKEY = None

CACHED_LOADS = {}

def increase_workload(r):
    key = ":workload:%s" % r.getClientIP()
    REDIS.incr(key, 1)
    REDIS.expire(key, 60 * 5)

def validate_workload(r):
    if "powq" in r.args and "powa" in r.args:
        q = base64.b64decode(r.args["powq"][0])
        a = r.args["powa"][0]

        q = PRIVKEY.decrypt(q, "EME1(SHA-1)")
        if q and q.split(",")[1] == a:
            return True

    return False


def get_load(w):
    if w not in CACHED_LOADS:
        CACHED_LOADS[w] = 2 ** (w + 12)
    return CACHED_LOADS[w]

def jsonify(r, obj, code=200):
    r.setHeader("Content-Type", "application/json")
    r.setResponseCode(code)
    r.write(json.dumps(obj))
    r.finish()

@defer.inlineCallbacks
def connect_redis():
    global REDIS
    REDIS = yield clientCreator.connectTCP(REDIS_HOST, REDIS_PORT)

def create_new_keypair():
    new_priv = botan.RSA_PrivateKey(1024, rng)
    new_pub = botan.RSA_PublicKey(new_priv)

    return (new_priv, new_pub)

def setup_server_keys():
    global PUBKEY, PRIVKEY
    if not os.path.exists("keys/pub.key") or not os.path.exists("keys/priv.key"):
        if not os.path.exists("keys"):
            os.mkdir("keys")

        priv, pub = create_new_keypair()

        PRIVKEY = priv
        PUBKEY = pub

        with open("keys/pub.key", "w") as f:
            f.write(pub.to_string())

        with open("keys/priv.key", "w") as f:
            f.write(priv.to_string())

        return

    with open("keys/priv.key", "r") as f:
        PRIVKEY = botan.RSA_PrivateKey(f.read(), rng)

    with open("keys/pub.key", "r") as f:
        PUBKEY = botan.RSA_PublicKey(f.read())

@defer.inlineCallbacks
def create_database_schema():
    USER_TABLE = """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY ASC,
        username TEXT,
        pubkey TEXT
    );
    """

    SESSION_TABLE = """
    CREATE TABLE sessions (
        id INTEGER PRIMARY KEY ASC,
        user INTEGER,
        created INTEGER
    )
    """

    data = yield dbpool.runQuery(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='users' OR name='sessions';")

    results = map(lambda i: i[0], data)

    if 'users' not in results:
        yield dbpool.runQuery(USER_TABLE)

    if 'sessions' not in results:
        yield dbpool.runQuery(SESSION_TABLE)

@route("/")
def home(r):
    return 'Hello, world!'

@route("/api/register")
@defer.inlineCallbacks
def register(r):
    if not validate_workload(r):
        jsonify(r, {
            "error": "Invalid or no Proof of Work!"
        }, 400)
        increase_workload(r)
        return

    username = r.args.get("username")[0]
    exists = yield dbpool.runQuery("SELECT count(*) FROM users WHERE username=? LIMIT 1",
        (username, ))

    if len(exists):
        jsonify(r, {
            "error": "Username already exists!"
        }, 400)
        increase_workload(r)
        return

    pub, priv = create_new_keypair()
    id = yield dbpool.runQuery("INSERT INTO users (username, pubkey) VALUES (?, ?)",
        (username, pub.to_string()))

    jsonify(r, {
        "id": id,
        "keys": {
            "public": pub.to_string(),
            "private": pub.to_string()
        }
    })

    increase_workload(r)


@route("/api/login")
def login(r):
    pass

@route("/api/logout")
def logout(r):
    pass

@route("/api/validate")
def validate(r):
    pass

@route("/api/hash")
@defer.inlineCallbacks
def hash(r):
    key = ":workload:%s" % r.getClientIP()

    ex = yield REDIS.get(key)
    load = get_load(int(ex or 1))

    hidden = str(random.randint(0, load))
    base = ','.join([str(time.time()), hidden, str(load)])
    encrypted_base = PUBKEY.encrypt(base, "EME1(SHA-1)", rng)
    digest = hashlib.sha512(hidden + encrypted_base).hexdigest()

    jsonify(r, {
        "load": load,
        "hash": digest.decode("utf-8"),
        "base": base64.b64encode(encrypted_base).decode("utf-8"),
    })
