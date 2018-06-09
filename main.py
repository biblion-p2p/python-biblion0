import os
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import PEMSerializationBackend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

import gevent

import libbiblion

# *~*~* Check configuration directory *~*~*
if not os.path.exists("data/"):
    os.mkdir("data")
    os.mkdir("data/keys")
    os.mkdir("data/pieces")

# *~*~* Load identity *~*~*

if not os.path.exists("data/keys/pub.key"):
    print("Missing public key. Generating new keypair.")

    # WARNING: The chosen curve here is considered insecure by DJB
    # Python cryptography library does not support proper curves
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )

    public_key = private_key.public_key()

    serialized_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    fpriv = open("data/keys/priv.key", 'wb')
    fpriv.write(serialized_private)
    fpriv.close()

    fpub = open("data/keys/pub.key", 'wb')
    fpub.write(serialized_public)
    fpub.close()
else:
    private_key_data = open("data/keys/priv.key", 'rb').read()
    private_key = serialization.load_pem_private_key(private_key_data,
                                                     None,
                                                     default_backend())

    public_key_data = open("data/keys/pub.key", 'rb').read()
    public_key = serialization.load_pem_public_key(public_key_data,
                                                   default_backend())

# *~*~* Connect to bootstrap node *~*~*
# TODO: Save list of peers from last time


#BOOTSTRAP_NODE = "127.0.0.1"
BOOTSTRAP_NODE = "biblion0-testnet/node0"
known_nodes = [BOOTSTRAP_NODE]

node_connections = []

for node in known_nodes:
    socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    #socket = socket.connect(node, "42069")
    node_connections.append(socket)

for conn in node_connections:
    libbiblion.dht_join(conn)
    # TODO handle

# TODO Contact bootstrap node
# TODO Get peers
# TODO Contact library leaders (if member of library)
# TODO Update blockchain state


# *~*~* Check database state *~*~*

# TODO Load extant piece data
# TODO Request data updates from library leaders

# TODO Publish data possession to DHT peers
