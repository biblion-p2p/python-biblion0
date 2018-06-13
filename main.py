from gevent.monkey import patch_all; patch_all();

import argparse
import json
import os
import sys
import socket

import gevent

import keygen
import libbiblion

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Biblion0 - ONLY FOR TESTING PURPOSES')
    parser.add_argument('--config', type=str, help='config file')
    parser.add_argument('--directory', type=str, help='directory for node')
    args = parser.parse_args()

    if not args.config or not args.directory:
        print("Config and directory are required")
        sys.exit(0)

    global_config = json.loads(open(args.config).read())

    original_directory = os.getcwd()  # needed for unix socket routing
    os.chdir(args.directory)

    # *~*~* Check configuration directory *~*~*
    if not os.path.exists("data/"):
        print("Creating data directory")
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

    node_connections = []  # XXX unused currently

    own_id = libbiblion.pub_to_nodeid(pub)
    print("STARTING BIBLION. NODE_ID", own_id)
    libbiblion.libbiblion_init(pub, priv)

    # TODO: generate self node id on startup. ensure don't add self as dht neighbor

    for node in known_nodes:
        if node[0] == own_id:
            # XXX need a stronger check
            # don't add self on DHT
            continue
        libbiblion.connect(original_directory + '/' + node[1])

    gevent.spawn(libbiblion.listen_for_connections)

    gevent.wait()

    # TODO Get peers / Initialize DHT
    # TODO Update blockchain state
    # TODO Contact library leaders (if member of library)


    # *~*~* Check database state *~*~*

    # TODO Load extant piece data
    # TODO Request data updates from library leaders

    # TODO Publish data possession to DHT peers
