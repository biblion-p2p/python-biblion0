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
import services.libbiblion
from client_api.json_rpc import start_json_rpc, shutdown_json_rpc
from biblion.identity import Identity
from biblion.library import Library
from log import log

# *~*~* Shutdown-signal handlers *~*~*
def async_suicide():
    # TODO this should wait until state is clean force exit after timeout
    log("Waiting 2 seconds then exiting")
    time.sleep(2)
    sys.exit(0)

def signal_handler(signal, frame):
        log('Shutting down...')
        gevent.spawn(shutdown_json_rpc)
        # XXX need to call shutdown on each transport
        #gevent.spawn(libbiblion.shutdown_sockets)
        gevent.spawn(identity.shutdown)
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

os.chdir(args.directory)
node_number = int(args.directory[-2:-1])

# *~*~* Check configuration directory *~*~*
if not os.path.exists("data/"):
    log("Creating data directory")
    os.mkdir("data")
    os.mkdir("data/keys")
    os.mkdir("data/pieces")

# *~*~* Load identity *~*~*
port = 8000 + (node_number * 2)
# TODO: Support multiple peer identities
addresses = {'ipv4': {'udp': [('127.0.0.1', port)],
                      'tcp': [('127.0.0.1', port)]}}
identity = Identity(keygen.get_keys(), addresses)

own_id = identity.get_own_id()
log("Starting. Our peer_id: %s" % own_id)

# *~*~* Start listening for messages *~*~*
identity.setup_transports()
gevent.spawn(start_json_rpc, port+1, identity)

# *~*~* Initialize global library *~*~*
global_library_spec = {
  "name": "_global",
  "routing": ["kademlia"],
  # todo: blockchain, blockchain publishing, kademlia PoW
  "download": ["bittorrent", "simple"]
}

global_lib = Library.create_library(global_library_spec, identity)

identity.register_library(global_lib)
# TODO register libraries from previous sessions
identity.start_libraries()

# *~*~* Connect to bootstrap node *~*~*
# TODO: Save list of peers from last time
#BOOTSTRAP_NODE = (("127.0.0.1 put something real here",,,
BOOTSTRAP_NODE = (global_config['bootstrap_node_id'], global_config['bootstrap_node_address'])
known_nodes = [BOOTSTRAP_NODE]

# XXX this shouldn't be necessary. bootstrap nodes should be hardsaved in PeerStore,
# and connection status should be requested by services
for node in known_nodes:
    if node[0] == own_id:
        continue
    peer = identity.add_or_get_peer(node[0], node[1])
    identity.services.get_service('_global.biblion').hello(identity, node)

gevent.wait()  # wait forever

# TODO in real implementation
# discover public ip address by either querying external service
#  or, check traceroute until encountering non-reserved IP address (WEAK BUT EFFECTIVE)
# need to open port using upnp or NATPMP
# alternatively, we can use UDP hole punching, then negotiate a TCP hole punch across a UDP channel
