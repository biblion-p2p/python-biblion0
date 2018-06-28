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


# node commands:
# ping
# kademlia_find_node
# kademlia_find_value
# kademlia_publish
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
                  'siblings': [],  # accounting for close nodes. We store 7k neighbors to ensure we know our neighborhood
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

def _kademlia_nearest_nodes(n):
    # keep returning neighbors near n until there are none left

    nearest_bucket = _kademlia_nearest_bucket(n)
    if nearest_bucket is None:
        print("requested nearest nodes to our own id")
        nearest_bucket = 0

    buckets = list(range(256))
    while buckets:
        for node in kademlia_state['k_buckets'][nearest_bucket]:
            yield node
        nearest_bucket = (nearest_bucket+1) % 256
        buckets.remove(nearest_bucket)

def _debug_k_trie_get():
    return kademlia_state['trie']

def _k_trie_remove_node(node_id):
    # Remove a node from the trie

    # TODO XXX None of this code is thread safe lol

    # TODO XXX this check should be put into whatever code calls this function
    #if node_id not in kademlia_state['active_nodes']:
    #    return

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
            last_parent['children'] = copy(old_branch['children'])
            last_parent['prefix'] = old_branch['prefix']
        else:
            last_parent['leaf'] = old_branch['leaf']
            last_parent['children'] = {}
        last_parent['count'] = old_branch['count']
        del old_branch
    else:  # root leaf
        current_node['leaf'] = None
        current_node['count'] = 0


def _k_trie_add_node(node_id):
    trie_root = kademlia_state['trie']

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
                branched_node = {'children': copy(current_node['children']),
                                 'prefix': current_node['prefix'],
                                 'leaf': None,
                                 'count': current_node['count']}
                current_node['count'] += 1
                current_node['children'][node_id[node_id_index]] = {'leaf': {'node_id': node_id},
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
            current_node['children'][node_id[node_id_index]] =  {'leaf': {'node_id': node_id},
                                                                 'children': {},
                                                                 'count': 1}
            return
        else:  # fresh trie
            current_node['leaf'] = {'node_id': node_id}
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
        # TODO XXX this can be replaced by the optimization below after testing
        return [trie_root['leaf']]

    # optimization: just return all nodes if less than k. TODO only enable after testing the normal way.
    # if len(kademlia_state['active_nodes']) <= KADEMLIA_K:
    #     return list(kademlia_state['active_nodes'].values())

    path = []
    used_prefixes = []

    current_node = trie_root
    while True:
        if len(results) == KADEMLIA_K:
            break

        if current_node['prefix'] not in used_prefixes and len(results) + current_node['count'] <= KADEMLIA_K:
            # Add all the nodes at this branch of the trie
            results.append(_k_trie_collect_leaves(current_node))
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


def _kademlia_add_node(request):
    """
    Adds a node record to our local k-buckets. Only call this after receiving
    a reply or request that indicates this node is alive.
    """
    # Adds a node to its kbucket.
    node_id = request['node_id']
    node_id_bin = base64.b64decode(node_id)
    ip = request['ip']
    # XXX port

    # TODO add the node to the trie

    """
    When we see a node in a response, we check if we have it in our global datastore by checking a global hashmap.

    If so, we update the node’s last-seen timestamp (using the reference from the hash map). If it’s in a K-bucket, we move it to the front of the k-bucket.

    If not, we check if it belongs in the sibling list. If not, we check its target k-bucket. We verify whether the other nodes in the list are live if needed.
    """


    nearest_bucket = _kademlia_nearest_bucket(node_id_bin)
    # XXX TODO If the bucket is full:
    #   Try to ping the least recently seen node. If it's alive, move it to most-recently seen and discard new entr
    kademlia_state['k_buckets'][nearest_bucket].append((node_id, ip))

def kademlia_find_node(request):
    """
    Finds the k nearest nodes in our kademlia database
    If we have less than k nodes, we return all of them
    """
    req_node = request['node_id']
    req_node_bin = base64.b64decode(req_node)
    local_nodeid_bin = base64.b64decode(pub_to_nodeid(public_key))

    # needed for old system: using k-bucket. use trie now. XXX delete the below line later
    #xor_result = [a ^ b for a, b in zip(req_node_bin, local_nodeid_bin)]

    # TODO: We can get the true list of closest nodes by looking through
    # a trie of all the ids we care to save

    # Trie traversal: iterate through prefix of req_node_bin. when we find a difference,
    # we pick all of the nodes in the leaf at that point. If there are less than
    # k, we backtrack and check if there are any leaves on the paths we skipped.
    # We stop when we have k nodes or have reached the root of the tree.

    # Example trie of known nodes. If we try to match something with a prefix of 0, we should return 011, then the ones from the other side.
    # It would be nice if we could quickly get a list of nodes from the other side of the trie. we can get the list by
    # iterating through the tree. This seems like it would be slow.
    # I guess this is why Mainline uses the strategy of the tree with lists at the leaves (representing the kbuckets)
    # In that system you can get to lists of nodes much more quickly.
    #  (null)
    # 0/        \1
    #(011)   0/  \1
    #     (100)  (110)

    # It should be possible to keep the trie without sacrificing the k buckets. At each bit, there will be a list stored representing the
    # kbucket.
    # Basically, we'll have the kbucket lists or tags to manage our accounting and node update schedules
    # And then we'll also have a list of n k-lists that represent the list of nodes for that bit prefix.
    # So if our node id was 0111xxx, we'd have lists for 1xxxx, 00xxx, and 010xx, 0110x, then finally 0111x
    # Basically, we choose the kbucket based on the first index of a different bit, just as before
    # The different would be that the size of these buckets might not be limited to K, so we'll need
    # a different structure for accounting. Hm.
    # There might actually be a lot of nodes in these lists. I guess that's where the trie makes the most
    # sense. Since a person might be a member of many libraries, a query for 1xxxx could have some nodes
    # that are closer to the query than others, but in this system they won't be sorted in any way. With
    # the trie, we can return a closer result.

    # 16 (K) * 256 (N) * 6 (L) = 24,576
    # A long live active node in 5 libraries might see around 25k nodes. I think
    # This the idea of a trie with a list of its children at each intermediate
    # node impossible. The size will explode.

    # Oh oh, what if we keep a sorted list of the nodes. Easy to do numerically.
    # Then we can use the trie to get an index into the list. Hell, the trie
    # leaves could be a doubly linked list, which would make inserting and
    # deleting a node easy!
    # Then, assuming 8 bytes for a pointer, the size of the trie would be 24576 * log_2(24576) * 8 =
    # 2.8675 million ~ 2.75 MiB
    # 3 megabytes for the trie and then k+log(n) lookup time doesn't sound that bad...
    # It's n*log(n) for the trie size

    # I need to check if this is actually an improvement. Is it better to give
    # ids of nodes in the left direction of the list? I've been assuming I'd
    # only move right through the list once finding the closest match in the trie.
    # But what if there's a jump moving from left to right? Should choosing the
    # nearest nodes be based on keeping the numerical distance low? This can
    # also be done in k time. We can keep track of the "left" and "right"
    # distance and choose whatever direction has the lowest distance. This
    # only requires two counters and two pointers.

    # Alright, now I just need to make sure choosing "closer" values actually
    # makes sense. I want to choose whatever keeps the overall query times low.
    # Unfortunately this will probably require experimentation.
    # (Note from later: Choosing the numerically closer path does not make
    # sense unfortunately. There's a big note in Notes where I worked through
    # a few examples. An intuitive way to think of the problem is that the
    # transition from 0111 to 1000 has a tiny numerical distance but a huge XOR
    # distance)

    # Limiting queries to within a library will also require changes.
    # I think each trie node would also need to keep separate pointers for the
    # next nodes in that libraries particular list. Otherwise, we'd have to
    # go through all the node in the list before deciding there are no more left.
    # This would mean node storage is multiplied by L in the worst case.



    # Old code: Looks through the kbuckets.
    # results = []
    # nearest_nodes = _kademlia_nearest_nodes(xor_result)
    # for node in nearest_nodes:
    #     results.append(node)
    #     if len(results) >= KADEMLIA_K:
    #         break
    results = []
    return results

def kademlia_ping():
    # TODO XXX This will be too expensive to do full TLS connections for every connection
    # Instead we should exchanged signed data over a UDP connection
    # The S/Kademlia paper has an interesting distrinction of weak signatures
    # That can be verifiably trasferred.
    connection = connections[node]
    msg = kademlia_generate_msg(FIND_NODE, node_id)
    connection.send_request(msg)

def kademlia_send_find_node(node):
    # TODO This should use the UDP port instead for performance
    connection = connections[node]
    msg = kademlia_generate_msg(FIND_NODE, node_id)
    connection.send_request(msg)

def kademlia_continue_lookup(lookup_id, msg):
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

    req_node_bin = base64.b64decode(node_id)
    local_nodeid_bin = base64.b64decode(pub_to_nodeid(public_key))

    xor_result = [a ^ b for a, b in zip(req_node_bin, local_nodeid_bin)]

    lookup_id = random()
    kademlia_lookups[lookup_id] = new_lookup_state()
    callback = lambda msg: kademlia_continue_lookup(lookup_id, msg)

    nearest_nodes = []
    for node in _kademlia_nearest_nodes(xor_result):
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

def kademlia_store():
    """
    Announcements will have to signed and timestamped. This way we can filter out
    outdated information in a reliable verifiable way, and ensure that announcements
    are always authenticated
    """
    pass

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
