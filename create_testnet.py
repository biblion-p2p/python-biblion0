# Create a testnetwork with multiple nodes connected via UNIX sockets
import os
import shutil
import base64
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

import keygen

if os.path.exists(".testnet"):
    shutil.rmtree(".testnet")

os.mkdir(".testnet")

NODES = 2

global_config = {}

for n in range(NODES):
    os.mkdir(".testnet/node%s" % n)
    os.mkdir(".testnet/node%s/data" % n)
    os.mkdir(".testnet/node%s/data/keys" % n)
    os.mkdir(".testnet/node%s/data/pieces" % n)
    if n == 0:
        pub, _ = keygen.get_keys(".testnet/node0")
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        pub_bits = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest.update(pub_bits)
        node_id = base64.b64encode(digest.finalize()).decode("utf-8")
        global_config['bootstrap_node_id'] = node_id

gc = open('.testnet/config.json', 'w')
gc.write(json.dumps(global_config))
gc.close()
