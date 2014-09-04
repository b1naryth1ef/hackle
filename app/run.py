from klein import run
from hackle import *

if __name__ == "__main__":
    create_database_schema()
    connect_redis()
    setup_server_keys()
    run("localhost", 5000)
