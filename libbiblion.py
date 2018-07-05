import base64
import json
import struct
import socket
import random
import os

from copy import copy

import http.server
import socketserver

import gevent
from flask import Flask

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec


# UDP commands:
# ping
# kademlia_find_node
# kademlia_find_value
# kademlia_publish

# TCP/connection commands:
# ping
# shelf_publish_data
# lynx_request_join
# lynx_accept_join
# lynx_submit_edit
# lynx_get_piece
# lynx_peer_exchange
# lynx_send_transaction
# biblion_sync_blockchain
# biblion_query_price
# biblion_announce_block
# biblion_send_transaction

# high level commands:
# initialize_dht

public_key = None
private_key = None
connections = {}
active_requests = {}

KADEMLIA_K = 16  # k-bucket size
KADEMLIA_D = KADEMLIA_K / 2  # number of disjoint paths. Similar to `alpha` in original kademlia paper
KADEMLIA_SIBLENGTH = KADEMLIA_K * 7  # number of entries in the sibling list
# sibling list should have size 7k (from S/Kademlia 4.2)
kademlia_state = {'trie': {'children': {}, 'leaf': None, 'count': 0},
                  'active_nodes': {},  # map of active nodes for quick node lookup
                  'k_buckets': {},  # accounting structure for managing far away nodes
                  'siblings': {'nodes': [], 'max': None},  # accounting for close nodes. We store 7k neighbors to ensure we know our neighborhood
                  'data_store': {}}  # values stored in our node. # XXX needs size constraint.
for i in range(256): kademlia_state['k_buckets'][i] = []

httpd_instance = None

def listen_for_connections():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        if os.path.exists(".socket"):
            os.remove(".socket")
        sock.bind(".socket")
        sock.listen(50)

        print("Now listening on domain socket")

        while True:
            conn, addr = sock.accept()
            print("Accepting new connection")
            gevent.spawn(handle_connection, conn)
            gevent.sleep(0)

# Messages will be handled asynchronously, like in libcircle. Each request has
# a number. We have to send a reply with the same request number. This allows
# us to have multiple requests and messages in flight at any time.

def listen_for_messages(node_id):
    conn = connections[node_id]
    while conn['connected']:
        message = recv_message(conn['socket'])
        # TODO handle disconnect
        if message['reqid']:
            # TODO Listeners can have expiration time
            reqid = message['reqid']
            if reqid in active_requests:
                # dispatch message
                active_requests[reqid](message)
                del active_requests[reqid]


def pub_to_nodeid(pubkey):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    pub_bits = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest.update(pub_bits)
    return base64.b64encode(digest.finalize()).decode("utf-8")

def get_pubbits():
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def libbiblion_init(pubkey, privkey):
    global public_key, private_key
    public_key = pubkey
    private_key = privkey

def encode_message(data):
    data = data.encode('utf-8')
    length = len(data)
    encoded_length = struct.pack('I', length)
    return encoded_length + data

def recv_message(sock):
    encoded_length = sock.recv(4)
    length = struct.unpack('I', encoded_length)[0]
    return sock.recv(length)

def handle_connection(client_socket):
    """
    Server-side of persistent connection handshake
    """

    global connections

    # Request 1: local public key, challenge
    req = recv_message(client_socket)
    message = json.loads(req)
    nonce_challenge = message['nonce']

    # Response 1: challenge answer, foreign public key, new challenge
    node_pubkey = serialization.load_pem_public_key(message['pub'].encode('utf-8'),
                                                    default_backend())
    nonce = random.randint(0, (2**32)-1)
    signature = private_key.sign(struct.pack('I', nonce_challenge),
                                 ec.ECDSA(hashes.SHA256()))
    resp = json.dumps({'pub': get_pubbits().decode('utf-8'),
                       'nonce': nonce,
                       'sig': base64.b64encode(signature).decode('utf-8')})
    client_socket.sendall(encode_message(resp))

    # Request 2: new challenge answer
    req2 = recv_message(client_socket)
    message2 = json.loads(req2)
    try:
        node_pubkey.verify(base64.b64decode(message2['sig']),
                           struct.pack('I', nonce),
                           ec.ECDSA(hashes.SHA256()))
    except:
        print("Signature of other node could not be verified")

    # End: ECDH
    shared_key = private_key.exchange(ec.ECDH(), node_pubkey)

    node_id = pub_to_nodeid(node_pubkey)
    print("Successfully connected to", node_id)
    connections[node_id] = {'pubkey': node_pubkey,
                            'session_key': shared_key,
                            'socket': client_socket,
                            'connected': True}

    listen_for_messages(node_id)


def connect(node):
    """
    Client-side of persistent connection handshake
    """

    global connections

    # WARNING: This can be MITM'd. The public key/id should be known before
    # connecting. This can be derived from the DHT list (or hardcoded for the bootstrap node(s))

    # Connect
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(node)

    # Request 1: local public key, challenge
    nonce = random.randint(0, (2**32)-1)
    req1 = json.dumps({'pub': get_pubbits().decode('utf-8'), 'nonce': nonce})
    sock.sendall(encode_message(req1))

    # Response 1: challenge answer, foreign public key, new challenge
    message = recv_message(sock)
    message = json.loads(message)
    node_pubkey = serialization.load_pem_public_key(message['pub'].encode('utf-8'),
                                                    default_backend())
    nonce_challenge = message['nonce']
    try:
        node_pubkey.verify(base64.b64decode(message['sig']),
                           struct.pack('I', nonce),
                           ec.ECDSA(hashes.SHA256()))
    except:
        print("Exception! Signature of other node could not be verified")

    # Request 2: new challenge answer
    signature = private_key.sign(struct.pack('I', nonce_challenge),
                                 ec.ECDSA(hashes.SHA256()))
    req2 = json.dumps({'sig': base64.b64encode(signature).decode('utf-8')})
    sock.sendall(encode_message(req2))

    # End: ECDH
    # WARNING WARNING the python cryptography library uses ephemeral ecdh (ECDHE),
    # which means it will generate the same shared secret every time!
    # Instead we should be establishing TLS connections between nodes
    shared_key = private_key.exchange(ec.ECDH(), node_pubkey)

    node_id = pub_to_nodeid(node_pubkey)
    print("Successfully connected to", node_id)
    connections[node_id] = {'pubkey': node_pubkey,
                            'session_key': shared_key,
                            'socket': sock,
                            'connected': True}

def send_message(conn, msg):
    conn.sendall(msg)

def send_request(conn, cb):
    active_requests[msg_id] = cb
    conn.send_message(msg)

def generate_request(command, data):
    pass

def _kademlia_nearest_bucket(n):
    # Returns the index of the most significant bit in the bytestring
    # Returns None if the bytestring doesn't belong in a bucket (it's the same as our nodeid)
    # XXX We should be able to find the nearest bucket faster using deBrujin sequences
    # http://supertech.csail.mit.edu/papers/debruijn.pdf
    for i, b in enumerate(n):
        e = 7
        while e > 0:
            if (b >> e) & 1:
                return ((31-i)*8) + e
            e -= 1

def _kademlia_nearest_nodes(node_id):
    # keep returning neighbors near n until there are none left
    node_id_bytes = base64.b64decode(node_id)
    node_id_bin = _util_convert_bytestring_to_bits(node_id)
    # optimization: just return all nodes if less than k. TODO only enable after testing the normal way.
    # if len(kademlia_state['active_nodes']) <= KADEMLIA_K:
    #     return list(kademlia_state['active_nodes'].values())
    return _k_trie_get_closest(node_id_bin)

def _k_trie_remove_node(node_id):
    # Remove a node from the trie

    # TODO XXX None of this code is thread safe lol

    trie_root = kademlia_state['trie']

    if trie_root['leaf'] and trie_root['leaf']['node_id'] != node_id:
        print("Trie does not have requested node")
        return
    elif not trie_root['leaf'] and not trie_root['children']:
        print("Empty trie")
        return

    node_id_index = 0
    current_node = trie_root
    last_parent = None
    while current_node['leaf'] is None:
        while node_id_index < len(current_node['prefix']):
            if current_node['prefix'][node_id_index] != node_id[node_id_index]:
                print("Node could not be found")
                return
            node_id_index += 1
        last_parent = current_node
        current_node['count'] -= 1
        current_node = current_node['children'][node_id[node_id_index]]

    if last_parent:
        other_branch = '0' if node_id[node_id_index] == '1' else '1'
        old_branch = last_parent['children'][other_branch]
        if old_branch['children']:
            last_parent['children'] = old_branch['children']
            last_parent['prefix'] = old_branch['prefix']
        else:
            last_parent['leaf'] = old_branch['leaf']
            last_parent['children'] = {}
        last_parent['count'] = old_branch['count']
        del old_branch
    else:  # root leaf
        current_node['leaf'] = None
        current_node['count'] = 0


def _k_trie_add_node(node_object):
    trie_root = kademlia_state['trie']
    node_id = node_object['node_id']

    node_id_index = 0
    current_node = trie_root
    while True:
        if current_node['children']:
            # The node is a branch node, iterate into branch
            while node_id_index < len(current_node['prefix']) and current_node['prefix'][node_id_index] == node_id[node_id_index]:
                node_id_index += 1

            if node_id_index == len(current_node['prefix']):
                # the prefix matches. iterate down.
                current_node['count'] += 1
                current_node = current_node['children'][node_id[node_id_index]]
            else:
                # new to add new branch here
                branched_node = {'children': current_node['children'],
                                 'prefix': current_node['prefix'],
                                 'leaf': None,
                                 'count': current_node['count']}
                current_node['count'] += 1
                current_node['children'][node_id[node_id_index]] = {'leaf': node_object,
                                                                    'children': {},
                                                                    'count': 1}
                current_node['children'][current_node['prefix'][node_id_index]] = branched_node
                current_node['prefix'] = current_node['prefix'][:node_id_index]  # truncate the prefix to represent the new branch
                return
        elif current_node['leaf'] and current_node['leaf']['node_id'] == node_id:
            # This ID is already in the trie. Give up.
            # TODO Maybe this should be where we update the record and kbuckets? Hmm, probably that should be in other code
            return
        elif current_node['leaf']:
            # We need to branch the trie at this point. We find the first
            # uncommon bitstarting at the current index and then branch at that
            # bit.
            while current_node['leaf']['node_id'][node_id_index] == node_id[node_id_index]:
                # This is safe because we check if the node ids are equal above.
                # There must be a difference in the nodes
                node_id_index += 1

            # Move current leaf into branch
            current_node['prefix'] = node_id[:node_id_index]
            current_node['children'][current_node['leaf']['node_id'][node_id_index]] = {'leaf': current_node['leaf'],
                                                                                        'children': {},
                                                                                        'count': 1}
            current_node['count'] += 1
            current_node['leaf'] = None

            # Add new node as child
            current_node['children'][node_id[node_id_index]] =  {'leaf': node_object,
                                                                 'children': {},
                                                                 'count': 1}
            return
        else:  # fresh trie
            current_node['leaf'] = node_object
            current_node['count'] = 1
            return


def _k_trie_collect_leaves(node):
    # in the real implementation this should probably be made iterative
    if node['leaf']:
        return [node['leaf']]
    else:
        return _k_trie_collect_leaves(node['children']['0']) + _k_trie_collect_leaves(node['children']['1'])

def _k_trie_get_closest(node_id):
    trie_root = kademlia_state['trie']
    results = []

    if trie_root['count'] == 0:
        # empty trie. just return
        return results

    if trie_root['leaf']:
        return [trie_root['leaf']]

    path = []
    used_prefixes = []

    current_node = trie_root
    while True:
        if len(results) == KADEMLIA_K:
            break

        if current_node['prefix'] not in used_prefixes and len(results) + current_node['count'] <= KADEMLIA_K:
            # Add all the nodes at this branch of the trie
            results.extend(_k_trie_collect_leaves(current_node))
            used_prefixes.append(current_node['prefix'])
            if path:
                current_node = path.pop()
                continue
            else:
                break

        if current_node['children']:
            # The node is a branch node, choose the best branch to iterate to
            branch_bit = node_id[len(current_node['prefix'])]
            n_branch_bit = '0' if branch_bit == '1' else '1'
            if current_node['prefix'] + branch_bit not in used_prefixes:
                next_node = current_node['children'][branch_bit]
                if next_node['leaf']:
                    results.append(next_node['leaf'])
                    used_prefixes.append(current_node['prefix'] + branch_bit)
                    continue
                else:  # branch
                    path.append(current_node)
                    current_node = next_node
            elif current_node['prefix'] + n_branch_bit not in used_prefixes:
                next_node = current_node['children'][n_branch_bit]
                if next_node['leaf']:
                    results.append(next_node['leaf'])
                    used_prefixes.append(current_node['prefix'] + n_branch_bit)
                    continue
                else:  # branch
                    path.append(current_node)
                    current_node = next_node
            else:
                if path:
                    current_node = path.pop()
                else:
                    break

    return results

def _kademlia_remove_node(node):
    # removes the node from its kbucket and from the trie
    if node['is_sibling']:
        kademlia_state['siblings'].remove(node)
    elif node['kbucket']:
        # remove it from the kbucket
        pass

    # TODO
    # remove the node from the active nodes list
    # remove the node from the trie

def _kademlia_queue_add(node):
    # TODO Queues a node for addition to our Kademlia state
    pass


def _kademlia_add_node(request):
    """
    When we see a node in a response, we check if we have it in our global datastore by checking a global hashmap.
    If so, we update the node’s last-seen timestamp (using the reference from the hash map). If it’s in a K-bucket, we move it to the front of the k-bucket.
    If not, we check if it belongs in the sibling list. If not, we check its target k-bucket. We verify whether the other nodes in the list are live if needed.
    """
    # TODO XXX make this thread safe
    node_id = request['node_id']
    node_id_bin = base64.b64decode(node_id)
    node_id_bits = _util_convert_bytestring_to_bits(node_id_bin)
    ip = request['ip']
    port = request['port']
    signature = request['signature']

    if node_id in kademlia_state['active_nodes']:
        # TODO should be moved to end of list?
        kademlia_state['active_nodes'][node_id]['last_seen_timestamp'] = time.time()
        return

    own_id = pub_to_nodeid(public_key)
    own_id_bin = base64.b64decode(own_id)
    xor_distance = [a^b for a, b in zip(own_id_bin, node_id_bin)]
    xor_distance_int = int.from_bytes(xor_distance, byte_order="big")

    new_node = {
        'node_id': node_id,
        'ip': ip,
        'port': port,
        'last_seen_timestamp': time.time()
    }

    if len(kademlia_state['siblings']['nodes']) < KADEMLIA_SIBLENGTH:
        kademlia_state['siblings']['nodes'].append(new_node)
        if xor_distance_int > kademlia_state['siblings']['max']:
            kademlia_state['siblings']['max'] = xor_distance

    if xor_distance_int < kademlia_state['siblings']['max']:
        # XXX O(n) performance sink :(
        for node in kademlia_state['siblings']:
            s_node_id = node['node_id']
            s_node_id_bin = base64.b64decode(s_node_id)
            s_xor_distance = [a^b for a, b in zip(own_id_bin, s_node_id_bin)]
            s_xor_distance_int = int.from_bytes(s_xor_distance, byte_order="big")
            if s_xor_distance_int == kademlia_state['siblings']['max']:
                _kademlia_remove_node(node)
                # Queue the node for re-addition. This will place it in the kbuckets
                _kademlia_queue_add(node)
                kademlia_state['siblings']['nodes'].append(new_node)
                kademlia_state['siblings']['max'] = xor_distance


    nearest_bucket = _kademlia_nearest_bucket(node_id_bin)
    if len(kademlia_state['k_buckets'][nearest_bucket]) < KADEMLIA_K:
        kademlia_state['k_buckets'][nearest_bucket].append((node_id, ip))
    else:
        # XXX TODO Try to ping the least recently seen node.
        # If it's alive, move it to most-recently seen and discard new entr

    # TODO add to trie if needed

def _util_convert_bytestring_to_bits(bytes):
    # this function shouldn't be needed in the rust version. we can just bit-twiddle in the trie
    result = ""
    for byte in bytes:
        current_byte = ""
        for n in range(8):
            bit = (byte >> n) & 1
            current_byte = "01"[bit] + current_byte
        result += current_byte
    return result

def kademlia_find_node(request):
    """
    Finds the k nearest nodes in our kademlia database
    If we have less than k nodes, we return all of them
    """
    req_node = request['node_id']
    results = _kademlia_nearest_nodes(req_node_bits)
    # TODO make response with signature
    return results

def kademlia_find_value(request):
    """
    Returns the value if we have it, or return the k nearest nodes to the node.
    """
    req_id = request['node_id']
    if req_id in kademlia_state['data_store']:
        results = kademlia_state['data_store']['req_id']
    else:
        results = _kademlia_nearest_nodes(req_node_bits)
    # TODO make response with signature
    return results

def kademlia_do_ping():
    connection = connections[node]
    msg = kademlia_generate_msg(PING, node_id)
    # TODO: needs to generate signature
    # TODO: wait for PONG response and confirm signature and address match of node
        # TODO: Need to create closure or request record with timeout
    connection.send_request(msg)

def kademlia_handle_ping(request):
    # TODO: try add_node
    # TODO send PONG response
    pass

def kademlia_send_find_node(node):
    # TODO This should use the UDP port instead for performance
    connection = connections[node]
    msg = kademlia_generate_msg(FIND_NODE, node_id)
    connection.send_request(msg)

def _kademlia_continue_lookup(lookup_id, msg):
    lookup_state = kademlia_lookups[lookup_id]
    # Continue lookup until the k nearest nodes have replied
    # TODO for S/Kademlia, I suppose we have to be smarter about disjoint paths?

def kademlia_do_lookup(node_id):
    # Get A nodes from closet k-buckets. Prefer taking from nearest k-bucket if possible.
    # Do parallel FIND_NODE requests to these A nodes.
    # The responses will have k entries (or less) for closest nodes
    # These should be added to a tentative list of nodes
    # Then we start requesting from these new, closer nodes
    # If we don't get any new nodes are closer than the ones we've already seen,
    # we continue querying until we get responses from K of the nearest nodes
    # that we've seen.
    # Note that after getting responses from nodes we should try to add to our
    # k-buckets if necessary

    # See SKademlia 4.4 for a more secure variant of this system
    # Need to consider disjoint paths specifically. This ensures that a single
    # adversarial node can't disrupt the system.

    # TODO, this function should be able to handle both FIND_NODE and FIND_VALUE

    lookup_id = random()
    kademlia_lookups[lookup_id] = new_lookup_state()
    callback = lambda msg: kademlia_continue_lookup(lookup_id, msg)

    nearest_nodes = []
    for node in _kademlia_nearest_nodes(node_id):
        nearest_nodes.append(node)
        if len(nearest_nodes) >= KADEMLIA_K:
            break

    # generate address lists for disjoint searches
    dpaths = {}
    for index, node in enumerate(nearest_nodes):
        current_d = n % index
        if current_d not in dpaths:
            dpaths[current_d] = []
        dpaths[current_d].append(node)

    for path in dpaths:
        pass
        # spawn greenthread for each path
        # they need to share a log of which servers have been queried (to remain disjoint)
        # The lookup terminates when the initiator has queried and gotten responses from the k closest nodes it has seen.
        # So we need to maintain a list of the closest nodes we've seen, and terminate when we've either queried them all
        # (in the case of less than k nodes), or have gotten responses from the k closest to our target
        # Ah, I see. In the end, the list should converge to k nodes that have all replied successfully.
        # As per usual, we can stop querying when we stop receiving closer results.

        kademlia_send_find_node(node, callback)

def kademlia_do_store():
    # Look up nearest nodes to ID.
    generate_store_request_and_sign
    nearest_nodes = kademlia_do_lookup(key_id)
    # Sends signed store request to each node
    send_to_all(nearest_nodes, store_request)

def kademlia_store(request):
    """
    Announcements will have to signed and timestamped. This way we can filter out
    outdated information in a reliable verifiable way, and ensure that announcements
    are always authenticated
    """

    if request['data']['timestamp'] < _24_hours_ago:
        # Ignore stale STOREs
        print("received stale STORE")
        return

    public_key = request['data']['pubkey']
    if not verify_signature(request['data'], public_key):
        print("received invalid STORE")
        return

    # TODO: enforce storage limits
    # TODO: eliminate old values if needed
    # TODO: STOREs should probably include a Proof-of-Work

    key = request['data']['key']
    value = (request_data['pubkey'], request['data']['ip'], request['data']['port'])
    kademlia_state['data_store'][key].append(value)

def initialize_dht(socket):
    # initialize global DHT
    # call find_node on self, adding neighbors until buckets are full or we run out of nodes to query

    # Add existing nodes
    _kademlia_add_node(known_nodes)

    """
    To join the network, a node u must have a contact to an already
    participating node w. u inserts w into the appropriate k-bucket. u then
    performs a node lookup for its own node ID. Finally, u refreshes all
    k-buckets further away than its closest neighbor. During the refreshes,
    u both populates its own k-buckets and inserts itself into other nodes’
    k-buckets as necessary.
    """
    kademlia_do_lookup(own_id)

    pass

class BiblionRPCRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/rpc':
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Only use /rpc please!\n")
            return

        response_data = ""
        if 'content-length' in self.headers:
            input_length = self.headers.get('content-length')
            input_data = self.rfile.read(int(input_length))
            parsed_data = json.loads(input_data)

            if 'command' in parsed_data:
                if parsed_data['command'] == 'print_dht':
                    response_data += "Current Kademlia DHT state:\n"
                    response_data += "Our node id: %s\n" % pub_to_nodeid(public_key)
                    response_data += json.dumps(kademlia_state)
                elif parsed_data['command'] == 'reset_dht':
                    pass
                elif parsed_data['command'] == 'dht_store':
                    pass
                elif parsed_data['command'] == 'dht_find_node':
                    response_data += json.dumps(kademlia_find_node(parsed_data))
                elif parsed_data['command'] == 'dht_find_value':
                    pass
                elif parsed_data['command'] == 'DEBUG__dht_add':
                    _kademlia_add_node(parsed_data)
                    response_data += 'SUCCESS'

        self.send_response(200)
        self.end_headers()

        if response_data:
            self.wfile.write(response_data.encode('utf-8'))

def shutdown_json_rpc():
    if httpd_instance:
        print("Shutting down JSON-RPC server")
        httpd_instance.shutdown()

def start_json_rpc(node_number):
    global httpd_instance
    port = 8000 + node_number

    with socketserver.TCPServer(("", port), BiblionRPCRequestHandler) as httpd:
        httpd_instance = httpd
        print("serving at port", port)
        try:
            httpd.serve_forever()
        except:
            print("Exception occurred in HTTP server")
        print("Cleaning up JSON-RPC TCPServer")

    httpd_instance = None
