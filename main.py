from gevent.monkey import patch_all; patch_all();

import argparse
import json
import os
import signal
import socket
import sys
import time

import gevent

import keygen
import libbiblion
from log import log
from identity import Identity

# *~*~* Shutdown-signal handlers *~*~*
def async_suicide():
    # TODO this should wait until state is clean force exit after timeout
    log("Waiting 2 seconds then exiting")
    time.sleep(2)
    sys.exit(0)

def signal_handler(signal, frame):
        log('Shutting down...')
        gevent.spawn(libbiblion.shutdown_json_rpc)
        gevent.spawn(libbiblion.shutdown_sockets)
        gevent.spawn(async_suicide)
signal.signal(signal.SIGINT, signal_handler)


# *~*~* Get arguments *~*~*
if __name__ != '__main__':
    log("Please run main.py on its own")
    sys.exit(0)

parser = argparse.ArgumentParser(description='Biblion0 - ONLY FOR TESTING PURPOSES')
parser.add_argument('--config', type=str, help='config file')
parser.add_argument('--directory', type=str, help='directory for node')
args = parser.parse_args()

if not args.config or not args.directory:
    log("Config and directory are required")
    sys.exit(0)

global_config = json.loads(open(args.config).read())

original_directory = os.getcwd()  # needed for unix socket routing
os.chdir(args.directory)
node_number = int(args.directory[-2:-1])

# *~*~* Check configuration directory *~*~*
if not os.path.exists("data/"):
    log("Creating data directory")
    os.mkdir("data")
    os.mkdir("data/keys")
    os.mkdir("data/pieces")

# *~*~* Load identity *~*~*
pub, priv = keygen.get_keys()

# *~*~* Connect to bootstrap node *~*~*
# TODO: Save list of peers from last time

#BOOTSTRAP_NODE = (("127.0.0.1 put something real here",,,
BOOTSTRAP_NODE = (global_config['bootstrap_node_id'], global_config['bootstrap_node_address'])
known_nodes = [BOOTSTRAP_NODE]

port = 8000 + (node_number * 2)
# TODO: Support multiple peer identities
addresses = {'ipv4': {'udp': [('127.0.0.1', port)],
                      'tcp': [('127.0.0.1', port)]}}
identity = Identity((pub, priv), addresses)

own_id = identity.pub_to_nodeid(pub)
log("STARTING BIBLION. NODE_ID %s" % own_id)
libbiblion.libbiblion_init(pub, priv)

for node in known_nodes:
    if node[0] == own_id:
        # XXX need a stronger check
        # don't add self on DHT
        continue
    peer = identity.add_or_update_peer(node[0], node[1])
    gevent.spawn(peer.connect)

gevent.spawn(identity._tcp_listen, port)
#gevent.spawn(libbiblion.listen_for_datagrams, port)
gevent.spawn(libbiblion.start_json_rpc, port+1)

gevent.wait()  # wait forever

# TODO Get peers / Initialize DHT
# TODO Contact library leaders (if member of library)
    # TODO Just need to see latest signed updates in the ledger. Can come from
    # any library members.
    # The blockchain is secured by consecutive hashses
    # Internal library state is governed by a dictator
    # Both can be represented as merkle objects in Biblion

# This should be done concurrently with global DHT bootstrap
for library in self.libraries:
    # sync user db
    library.sync_user_state()
    # at this point (or at least within some condifence), we can enable the virtual dht for this library
    # sync ledger
    library.sync_transaction_state()
    # sync metadata
    # XXX must sync library config as well
    for data_id in library.metadata:
        library.sync_data_item(data_id)

 #TODO LATER
# TODO Update blockchain state

# TODO
# Need to make kademlia implementation mostly safe from DDoS


# TODO in real implementation
# discover public ip address by either querying external service
#  or, check traceroute until encountering non-reserved IP address (WEAK BUT EFFECTIVE)
# need to open port using upnp or NATPMP
# alternatively, we can use UDP hole punching, then negotiate a TCP hole punch across a UDP channel

# *~*~* Check database state *~*~*
for file in database:
    # verify present
    # queue announcement on dhts as needed
    pass
