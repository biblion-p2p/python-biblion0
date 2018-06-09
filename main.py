import os
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import PEMSerializationBackend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

import gevent

import keygen
import libbiblion

# TODO chdir to node directory

# *~*~* Check configuration directory *~*~*
if not os.path.exists("data/"):
    os.mkdir("data")
    os.mkdir("data/keys")
    os.mkdir("data/pieces")

# *~*~* Load identity *~*~*
pub, priv = keygen.get_keys()

# *~*~* Connect to bootstrap node *~*~*
# TODO: Save list of peers from last time

#BOOTSTRAP_NODE = "127.0.0.1"
BOOTSTRAP_NODE = ".testnet/node0"
known_nodes = [BOOTSTRAP_NODE]

node_connections = []

for node in known_nodes:
    socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    #socket = socket.connect(node, "42069")
    node_connections.append(socket)

for conn in node_connections:
    pass
    #libbiblion.dht_join(conn)
    # TODO handle

# TODO Get peers
# TODO Contact library leaders (if member of library)
# TODO Update blockchain state


# *~*~* Check database state *~*~*

# TODO Load extant piece data
# TODO Request data updates from library leaders

# TODO Publish data possession to DHT peers
