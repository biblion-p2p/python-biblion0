# Create a testnetwork with multiple nodes connected via UNIX sockets
import os
import shutil
import base64
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

import keygen
import libbiblion

if os.path.exists(".testnet"):
    shutil.rmtree(".testnet")

os.mkdir(".testnet")

NODES = 3

global_config = {}

for n in range(NODES):
    os.mkdir(".testnet/node%s" % n)
    os.mkdir(".testnet/node%s/data" % n)
    os.mkdir(".testnet/node%s/data/keys" % n)
    os.mkdir(".testnet/node%s/data/pieces" % n)
    if n == 0:
        pub, _ = keygen.get_keys(".testnet/node0")
        global_config['bootstrap_node_id'] = libbiblion.pub_to_nodeid(pub)
        global_config['bootstrap_node_address'] = '.testnet/node0/.socket'

gc = open('.testnet/config.json', 'w')
gc.write(json.dumps(global_config))
gc.close()
