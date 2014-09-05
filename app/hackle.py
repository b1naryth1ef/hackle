import json, time, hashlib, random, os, base64
from klein import route
from twisted.internet import defer
from twisted.enterprise import adbapi
from twisted.internet import protocol
from twisted.internet import reactor
import txredis

import nacl.utils
from nacl.public import PrivateKey, Box, PublicKey
from nacl.encoding import Base64Encoder

dbpool = adbapi.ConnectionPool("sqlite3", "hek.db", check_same_thread=False)
clientCreator = protocol.ClientCreator(reactor, txredis.HiRedisClient)

REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS = None

SERVER_KEY = None
CACHED_LOADS = {}

def increase_workload(r):
    key = ":workload:%s" % r.getClientIP()
    REDIS.incr(key, 1)
    REDIS.expire(key, 60 * 5)

def validate_workload(r):
    if "powq" in r.args and "powa" in r.args:
        q = base64.b64decode(r.args["powq"][0])
        a = r.args["powa"][0]

        box = Box(SERVER_KEY, SERVER_KEY.public_key)
        q = box.decrypt(q)
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
    return PrivateKey.generate()

def setup_server_keys():
    global SERVER_KEY
    if not os.path.exists("keys/server.key"):
        if not os.path.exists("keys"):
            os.mkdir("keys")

        SERVER_KEY = create_new_keypair()

        with open("keys/server.key", "w") as f:
            f.write(SERVER_KEY._private_key)

        return

    with open("keys/server.key", "r") as f:
        SERVER_KEY = PrivateKey(f.read().strip())

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
    );
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

    if len(exists) and exists[0][0] != 0:
        jsonify(r, {
            "error": "Username already exists!"
        }, 400)
        increase_workload(r)
        return

    priv = create_new_keypair()
    id = yield dbpool.runQuery("INSERT INTO users (username, pubkey) VALUES (?, ?)",
        (username, base64.b64encode(str(priv.public_key))))

    jsonify(r, {
        "id": id,
        "key": base64.b64encode(priv._private_key)
    })

    increase_workload(r)

@route("/api/login")
@defer.inlineCallbacks
def login(r):
    if not validate_workload(r):
        jsonify(r, {
            "error": "Invalid or no Proof of Work!"
        }, 400)
        increase_workload(r)
        return

    if "payload" not in r.args:
        jsonify(r, {
            "error": "Invalid login request!"
        }, 400)
        increase_workload(r)
        return

    username = r.args.get("username", [])[0]

    user = yield dbpool.runQuery("SELECT id, pubkey FROM users WHERE username=? LIMIT 1",
        (username, ))

    if not len(user):
        jsonify(r, {
            "error": "Invalid Username!"
        }, 400)
        increase_workload(r)
        return

    user_pub_key = PublicKey(base64.b64decode(user[0][1]))
    enc_content = base64.b64decode(r.args["payload"][0])
    box = Box(SERVER_KEY, user_pub_key)
    raw = json.loads(box.decrypt(enc_content))

    if (time.time() - raw["timestamp"]) > 60:
        jsonify(r, {
            "error": "Timestamp is older than 60 seconds!"
        }, 400)
        increase_workload(r)
        return

    yield dbpool.runQuery("INSERT INTO sessions (user, created) VALUES (?, ?)",
        (user[0][0], time.time()))
    res = yield dbpool.runQuery("SELECT last_insert_rowid() FROM sessions")

    jsonify(r, {
        "id": res[0][0]
    })


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
    nonce = nacl.utils.random(Box.NONCE_SIZE)

    box = Box(SERVER_KEY, SERVER_KEY.public_key)
    encrypted_base = box.encrypt(base, nonce)
    digest = hashlib.sha512(hidden + encrypted_base).hexdigest()

    jsonify(r, {
        "load": load,
        "hash": digest.decode("utf-8"),
        "base": base64.b64encode(encrypted_base).decode("utf-8"),
    })

@route("/api/info")
def info(r):
    jsonify(r, {
        "key": base64.b64encode(str(SERVER_KEY.public_key)),
    })
