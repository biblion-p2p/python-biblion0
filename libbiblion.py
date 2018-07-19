import base64
import json
import struct
import socket
import random
import os
import time

from copy import copy

import http.server
import socketserver

import gevent
from gevent.event import Event
from flask import Flask

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



public_key = None
private_key = None
connections = {}
active_streams = {}
_next_stream_id = 1

KADEMLIA_K = 16  # k-bucket size
KADEMLIA_D = KADEMLIA_K / 2  # number of disjoint paths. Similar to `alpha` in original kademlia paper
KADEMLIA_SIBLENGTH = KADEMLIA_K * 7  # number of entries in the sibling list
# sibling list should have size 7k (from S/Kademlia 4.2)
kademlia_state = {'trie': {'children': {}, 'leaf': None, 'count': 0},
                  'active_nodes': {},  # map of active nodes for quick node lookup
                  'k_buckets': {},  # accounting structure for managing far away nodes
                  'siblings': {'nodes': [], 'max': 0},  # accounting for close nodes. We store 7k neighbors to ensure we know our neighborhood
                  'data_store': {}}  # values stored in our node. # XXX needs size constraint.
for i in range(256): kademlia_state['k_buckets'][i] = []

httpd_instance = None
tcp_socket = None

_global_port = None

def listen_for_connections(port):
    # lmao, this hack should absolutely not be here
    global _global_port
    _global_port = port
    # XXX Listening on ipv6 should help remove NAT troubles, but it probably isn't widely supported
    global tcp_socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        tcp_socket = sock
        sock.bind(("127.0.0.1", port))
        sock.listen(50)

        print("Now listening on TCP socket", port)

        while True:
            conn, addr = sock.accept()
            print("Accepting new connection")
            gevent.spawn(handle_connection, conn)
            gevent.sleep(0)

def listen_for_datagrams(port):
    # UDP messages can be DHT messages, or messages in a DTLS session (useful for getting around NAT)
    # TODO XXX We should also support uTP streams at some point. QUIC looks great. Supports transport-layer multiplexing
    # Also check out UDP over ipv6, including with IPsec.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", port))

        print("Now listening on UDP socket", port)

        while True:
            # should probably set message state and include address or some shit
            # that way we can check "connection" info even on a connectionless basis
            (message, _, _, address) = sock.recvmsg(65536)
            # TODO XXX need to generate conn context
            # It can be a pseudo connection, but it needs to have the context of how to reply to the message
            handle_message(conn, message)


# Messages will be handled asynchronously. Each request has
# a number. We have to send a reply with the same request number. This allows
# us to have multiple requests and messages in flight at any time.

def listen_for_messages(node_id):
    conn = connections[node_id]
    while conn['connected']:
        message = recv_message(conn['socket'])
        message = sym_decrypt(message, conn['session_key'])
        handle_message(conn, message)
        # TODO handle disconnect

def handle_message(conn, message):
    # For now, each message will be a JSON object describing the packet
    # Each packet should have a streamId that represents an RPC or data flow

    global active_streams

    # TODO Streams can have expiration time
    message = json.loads(message)
    inner_msg = message['data']
    stream_id = message['streamId']
    if stream_id in active_streams:
        stream = active_streams[stream_id]
        stream['data'].append(inner_msg)
        stream['event'].set()
    else:
        active_streams[stream_id] = {'data': [inner_msg],
                                     'event': Event(),
                                     'open': True,
                                     'conn': conn,
                                     'header': build_stream_header_from_message(message)}
        gevent.spawn(handle_new_request, active_streams[stream_id])

    if 'closeStream' in message:
        active_streams[stream_id]['open'] = False
        del active_streams[stream_id]

def handle_new_request(stream):
    """
    Temporary generic request handler for biblion.
    Protocol 1 (Though protocol number isn't even used yet, as of this comment).
    Each message has a type and a payload.
    The type should eventually be mostly elevated to the streaming layer, with
    message signaling handled per application.
    """

    message = stream['data'].pop()
    mt = message['type']

    # over udp
    if mt == 'ping':
        pass
    elif mt == 'hello':
        handle_hello(stream, message['payload'])
    elif mt == 'kademlia_find_node':
        kademlia_find_node(stream, message['payload'], query="node")
    elif mt == 'kademlia_find_value':
        kademlia_find_node(stream, message['payload'], query="value")
    elif mt == 'kademlia_publish':
        kademlia_store(stream, message['payload'])
    # over TCP
    elif mt == 'shelf_publish_data':
        pass
    elif mt == 'lynx_request_join':
        # TODO XXX this should be based on a higher level p2p messaging system
        # maybe called something like "metalib"
        pass
    elif mt == 'lynx_accept_join':
        # TODO XXX see above
        pass
    elif mt == 'lynx_submit_edit':
        # TODO XXX see above
        pass
    elif mt == 'lynx_get_pieces':
        # Request a range of pieces
        # should implement dynamic choke algorithm
        # check out libtorrent. they have a good one for seeding that prefers peers who just started or who are about to finish
        #https://github.com/arvidn/libtorrent/blob/master/src/choker.cpp
        lynx_get_pieces(request)
    elif mt == 'lynx_peer_exchange':
        # Return known peers that have the same content. Useful for swarm management
        pass
    elif mt == 'lynx_send_transaction':
        #
        pass
    elif mt == 'biblion_sync_blockchain':
        # Return what the most recent block number is
        pass
    elif mt == 'biblion_query_price':
        # should specify what we have in a request.
        # response should in include what they have and if they accept our proposal.
        pass
    elif mt == 'biblion_announce_block':
        pass
    elif mt == 'biblion_send_transaction':
        pass


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
    if type(data) == str:
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

    global connections, _next_stream_id

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
    ip, port = client_socket.getpeername()
    print("Successfully connected to", node_id)
    connections[node_id] = {'pubkey': node_pubkey,
                            'node_id': node_id,
                            'session_key': shared_key,
                            'ip': ip,
                            'port': port,
                            'type': 'listener',
                            'socket': client_socket,
                            'connected': True}

    _next_stream_id += 1  # listener uses even stream IDs
    listen_for_messages(node_id)


def connect(node):
    """
    Client-side of persistent connection handshake
    """

    global connections

    # WARNING: This can be MITM'd. The public key/id should be known before
    # connecting. This can be derived from the DHT list (or hardcoded for the bootstrap node(s))

    # Connect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((node['address'], node['port']))

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
    connections[node_id] = {'node_id': node_id,
                            'pubkey': node_pubkey,
                            'session_key': shared_key,
                            'ip': node['address'],
                            'port': node['port'],
                            'socket': sock,
                            'type': 'dialer',
                            'connected': True}

    gevent.spawn(listen_for_messages, node_id)
    send_hello(connections[node_id])

def collect_addresses(node_id):
    """
    Returns the internet addresses for the given peer id. This returns addresses
    for the currently running node.
    """
    return {'ipv4': [('127.0.0.1', _global_port)]}

def collect_protocols(node_id):
    """
    Returns the library:protocol pairs for the given node id. This represents
    nodes running on our current instance
    """
    # XXX TODO actually check what libraries we are a member of.
    return {'_global': ['dht']}

def send_hello(conn):
    # message should include our public addresses, our public library memberships, and our services for each library

    message = {'type': 'hello',
               'payload': {
                    # TODO XXX need to get our current peer id for the current connection
                   'addrs': collect_addresses(None),
                   'libraries': collect_protocols(None)
               }}

    response = send_request_sync(conn, message)
    response = response[0]['payload']
    print("got HELLO response")

    # TODO process library memberships in response or something
    conn['addrs'] = response['addrs']
    _kademlia_add_node(conn)

def handle_hello(stream, request):
    # record libraries and services provided by node

    print("Handling HELLO")

    stream['conn']['addrs'] = request['addrs']
    response = {'type': 'hello',
                'payload': {'addrs': collect_addresses(None),
                            'libraries': collect_protocols(None)}}
    response_obj = copy(stream['header'])
    response_obj['data'] = response
    response_obj['closeStream'] = True
    send_message(stream['conn'], response_obj)
    _kademlia_add_node(stream['conn'])

_signed_id = None
def _get_signed_id():
    global _signed_id
    if not _signed_id or _signed_id['timestamp'] > _1_hour_ago:
        id = {'node_id': own_id,
              'address': {'family': 'ipv4', 'nat': 'open', 'address': get_address(), 'port': get_port()},
              'timestamp': timestamp_now()}
        json_id = json.dumps(id, sort_keys=True)
        signature = sign(json_id)
        _signed_id = {'id' : id, 'sig': signature}
    # otherwise, generate an object with our address (family, nat, address, port), a timestamp, and a signature
    return _signed_id

_next_req_id = 1
def send_datagram(address, port, message, is_request=False):
    message['from'] = _get_signed_id()
    if is_request:
        message['req_id'] = _req_id
        _next_req_id += 1
    encoded_message = json.dumps(message, sort_keys=True)
    dsock.sendto(message, (address, port))

def sym_decrypt(message, key):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(b'\x01', message, None)

def sym_encrypt(message, key):
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(b'\x01', message, None)

def send_message(conn, message):
    message = json.dumps(message).encode('utf-8')
    enc_msg = encode_message(sym_encrypt(message, conn['session_key']))
    conn['socket'].sendall(enc_msg)

def build_stream_header_from_message(message):
    return build_stream_header(message['protocolId'],
                               message['streamId'],
                               message.get('libraryId'))

def build_stream_header(protocol_id, stream_id, library_id):
    header = {'protocolId': protocol_id, 'streamId': stream_id}
    if library_id:
        header['libraryId'] = library_id
    return header

def create_stream(conn, protocol_id, library_id=None):
    global _next_stream_id
    active_streams[_next_stream_id] = {'data': [],
                                       'event': Event(),
                                       'open': True,
                                       'conn': conn}
    header = build_stream_header(protocol_id, _next_stream_id, library_id)
    active_streams[_next_stream_id]['header'] = header
    msg_id = _next_stream_id
    _next_stream_id += 2
    return msg_id

def send_request_sync(conn, request):
    # Sends a request and waits for a response from the remote peer.
    # Create a stream context with a protocol and library information
    # These will be used to initialize the stream
    # Send the request in the first packets.
    # Await the response from the other side.

    stream_id = create_stream(conn, 1)  # TODO XXX protocol 1 is generic Biblion protocol
    message = copy(active_streams[stream_id]['header'])
    message['openStream'] = True
    message['data'] = request
    send_message(conn, message)

    stream = active_streams[stream_id]
    while stream['open']:
        stream['event'].wait()
        stream['event'].clear()

    return stream['data']

def start_bank(library):
    # this function probably isn't needed but i wanted to write some notes
    # read current bank state
    # need to be able to add transactions if correct
    # need to be able to create payment channels
    # need to be able to update payment channel amounts
    # need to close payment channel on request of recipient
    # need to close payment channel after timeout
    # need to broadcast bank updates to all peers
    pass

def do_fetch(fetch_data):
    if fetch_data.is_library and library.has_custom_routing:
        peers = library.router.get_peers
        if peers.failed:
            global_dht.get_peers
    else:
        peers = global_dht.get_peers

    connected_peers = peers.choose_random(10) # we connect to many peers to query their ownership, but will only download from 5
    # TODO: At this point we should announce ourselves to the DHT. Hm, maybe this can be piggybacked on the FINDVALUE?

    for p in connected_peeers:
        # TODO XXX, we should wait for at least 5 peers to respond and choose the ones with the lowest ping. warning: those chosen nodes may have bad pricing!
        p = p.connect
        res = p.query_data(fetch_data.id)
        if res.has_data:
            price = res.price
            # TODO need to confirm price is correct. to start, we can simply use bits as price, and disconnect from nodes that misbehave
            p.mark_active(fetch_data.id)
            while p.is_active: # ie, unchoked
                for pieces in fetch_state.rarest_pieces(p, p.trust):  # get some rare pieces from the node based on their trust. if they behave well, we request more.
                    payment_channel = None
                    if p.is_library_node(fetch_data.library) and library.needs_payment():
                        if p.has_payment_channel(piece):
                            payment_channel = p.payment_channel
                        else:
                            payment_channel = library.create_payment_channel(p, piece, 5)

                        for piece in pieces:  # TODO parallelize based on trust
                            payment_channel.add_signature(piece)  # bump up the authorized transaction amount. MUST BE THREAD SAFE!
                            p.get_block(piece, payment_channel)
                            p.trust += 1  # increase outstanding requests
                            if p.newly_choked:
                                p.abort_download  # wait for existing stuff to stop, then choose new peer

                    p.request_piece(piece, payment_channel)
        else:
            # mark the node as unneeded. it can be pruned or kept active for gossip, etc
            # should send goaway if truly unneeded
            p.mark_as_unneeded()


def lynx_get_piece(request):
    # TODO XXX probably should remove this. there will be an internal piece requester
    pass


def lynx_get_pieces(request):
    # this should probably be renamed "query_pieces". We return which pieces are available in the requested set
    # returns what pieces we have
    for piece in request['pieces']:
        if have_data(piece):
            pass


def _kademlia_nearest_bucket(n):
    # Returns the index of the most significant bit in the bytestring
    # Returns None if the bytestring doesn't belong in a bucket (it's the same as our nodeid)
    # XXX We should be able to find the nearest bucket faster using deBrujin sequences
    # http://supertech.csail.mit.edu/papers/debruijn.pdf
    n = n.to_bytes(32, byteorder="big")
    for i, b in enumerate(n):
        e = 7
        while e > 0:
            if (b >> e) & 1:
                return ((31-i)*8) + e
            e -= 1

def _kademlia_nearest_nodes(node_id):
    # keep returning neighbors near n until there are none left
    node_id_bin = _util_nodeid_to_bits(node_id)
    # optimization: just return all nodes if less than k. TODO only enable after testing the normal way.
    # if len(kademlia_state['active_nodes']) <= KADEMLIA_K:
    #     return list(kademlia_state['active_nodes'].values())
    return _k_trie_get_closest(node_id_bin)

def _k_trie_remove_node(node_id_bin):
    # Remove a node from the trie

    # TODO XXX None of this code is thread safe lol

    trie_root = kademlia_state['trie']

    if trie_root['leaf'] and trie_root['leaf']['node_id'] != node_id_bin:
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
            if current_node['prefix'][node_id_index] != node_id_bin[node_id_index]:
                print("Node could not be found")
                return
            node_id_index += 1
        last_parent = current_node
        current_node['count'] -= 1
        current_node = current_node['children'][node_id_bin[node_id_index]]

    if last_parent:
        other_branch = '0' if node_id_bin[node_id_index] == '1' else '1'
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
    node_id = node_object['node_id_bin']

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

def _node_xor_distance(node1, node2):
    # expects base64 node ids
    # returns an integer representing the XOR distance
    n1b = base64.b64decode(node1)
    n2b = base64.b64decode(node2)
    xor = [a^b for a, b in zip(n1b, n2b)]
    return int.from_bytes(xor, byteorder="big")


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
    # TODO check where this is called and make sure signature is checked where needed
    # TODO Queues a node for addition to our Kademlia state
    # This is needed to ensure we limit lock contention on the trie, etc
    pass


def _kademlia_add_node(request):
    """
    When we see a node in a response, we check if we have it in our global datastore by checking a global hashmap.
    If so, we update the node’s last-seen timestamp (using the reference from the hash map). If it’s in a K-bucket, we move it to the front of the k-bucket.
    If not, we check if it belongs in the sibling list. If not, we check its target k-bucket. We verify whether the other nodes in the list are live if needed.
    """
    # TODO XXX make this thread safe
    node_id = request['node_id']
    own_id = pub_to_nodeid(public_key)

    if node_id == own_id:
        # We don't add ourselves to the DHT. It's unnecessary
        return

    addresses = request['addrs']

    if node_id in kademlia_state['active_nodes']:
        # TODO should be moved to end of list?
        kademlia_state['active_nodes'][node_id]['last_seen_timestamp'] = time.time()
        return
    xor_distance_int = _node_xor_distance(own_id, node_id)

    new_node = {
        'node_id': node_id,
        'node_id_bin': _util_nodeid_to_bits(node_id),
        'addrs': addresses,
        'last_seen_timestamp': time.time()
    }

    nearest_bucket_id = _kademlia_nearest_bucket(xor_distance_int)
    nearest_bucket = kademlia_state['k_buckets'][nearest_bucket_id]

    if len(kademlia_state['siblings']['nodes']) < KADEMLIA_SIBLENGTH:
        kademlia_state['siblings']['nodes'].append(new_node)
        if xor_distance_int > kademlia_state['siblings']['max']:
            kademlia_state['siblings']['max'] = xor_distance_int
    elif xor_distance_int < kademlia_state['siblings']['max']:
        # XXX O(n) performance sink :(
        # find the max and kick it out into the k buckets
        for node in kademlia_state['siblings']:
            sibling_distance = _node_xor_distance(own_id, node['node_id'])
            if s_xor_distance_int == kademlia_state['siblings']['max']:
                _kademlia_remove_node(node)
                # Queue the node for re-addition. This will place it in the kbuckets
                _kademlia_queue_add(node)
                kademlia_state['siblings']['nodes'].append(new_node)
                kademlia_state['siblings']['max'] = xor_distance_int
    elif len(nearest_bucket) < KADEMLIA_K:
        nearest_bucket.append(new_node)
    else:
        least_recently_seen = nearest_bucket[-1]
        alive = kademlia.ping(least_recently_seen)
        if alive:
            # TODO XXX ensure the ping result updated the node in the list if alive
            # K bucket is full. Abort add
            return
        else:
            # TODO XXX ensure the ping result removed the node
            nearest_bucket.append(new_node)  # add the new node

    # Add the node to the trie
    _k_trie_add_node(new_node)

def _util_nodeid_to_bits(node_id):
    node_id_bytes = base64.b64decode(node_id)
    return _util_convert_bytestring_to_bits(node_id_bytes)

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

def kademlia_find_node(request, query=None):
    """
    Finds the k nearest nodes in our kademlia database
    If we have less than k nodes, we return all of them
    """

    if not query:
        print("FIND query should specify NODE or VALUE")
        return

    # TODO XXX enable when using UDP DHT
    # if request.signature.address == message.address:
    #     _kademlia_queue_add(request)
    req_node = request['node_id']
    if query == 'value' and req_node in data_store:
        result = data_store.get(req_node)
        return result
    results = _kademlia_nearest_nodes(req_node)
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
        results = _kademlia_nearest_nodes(req_node)
    # TODO make response with signature
    return results

def kademlia_do_ping():
    connection = connections[node]
    msg = kademlia_generate_msg(PING, node_id)
    # TODO: needs to generate signature
    # TODO: wait for PONG response and confirm signature and address match of node
        # TODO: Need to create closure or request record with timeout
    connection.send_request(msg)

def kademlia_ping(request):
    """ Handle ping """
    # need to have address state from message receiver
    if request.signature.address == message.address:
        _kademlia_queue_add(request)
    send_message(generate_kademlia_pong(request))

def kademlia_send_find_node(node_info):
    msg = kademlia_generate_msg(FIND_NODE, node_id)
    if node.is_connected:
        node.send_request(msg)
    else:
        # TODO use UDP. This should be abstracted away as far as possible
        address, port = get_ipv4_address(node)
        send_datagram(msg, address)
        connection.send_request(msg)

def _kademlia_continue_lookup(lookup_id, msg):
    lookup_state = kademlia_lookups[lookup_id]
    # Continue lookup until the k nearest nodes have replied
    # TODO for S/Kademlia, I suppose we have to be smarter about disjoint paths?

def kademlia_do_lookup(node_id):
    # TODO, this function should be able to handle both FIND_NODE and FIND_VALUE

    # lookup_id = random()
    # kademlia_lookups[lookup_id] = new_lookup_state()
    # callback = lambda msg: kademlia_continue_lookup(lookup_id, msg)

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

    # this need to be shared among threads to keep paths disjoint
    # TODO: we should probably have a limiter for IP address to prevent sybil. though a few on same ip is fine
    accessed_nodes = []

    def _xor_with(node_id):
        return lambda n: _node_xor_distance(node_id, n)

    for path in dpaths:  # greenlet for each
        sorted_path = sorted(path, key=_xor_with(own_id))
        for node in sorted_path:
            if not node.accessed:
                node = n
                break
            if index == KADEMLIA_K:
                return path.sorted[:KADEMLIA_K]
        else:
            # found less than k
            return path.sorted
        node = path.sorted.pop(0)  # sorted by XOR distance from target
        accessed_nodes.append(node)  # synchronized
        new_nodes = kademlia_send_find_node(node, callback)
        # TODO XXX need to enable this for UDP kademlia
        #if confirm_sig(node):
        #   _kademlia_queue_add(node)

        # TODO XXX I think this is for when this code should support FIND_VALUE
        #if node_id in new_nodes:
        #    return
        path.sorted.add(new_nodes)

def kademlia_do_random_walk():
    # For each bucket farther away than the closest populated one, choose a random
    # id in that range and do a lookup on it

    # TODO XXX
    return

    for bucket in sorted(kademlia_state['k_buckets'])[::-1]:
        if kademlia_state['k_buckets'][bucket]:
            closest_bucket = bucket
            break
    else:
        print("No K-buckets populated? Oh no...")
        return

    for i in range(closest_bucket):
        rand_id = generate_random_value_for_bucket(i)
        kademlia_do_lookup(rand_id)


def kademlia_do_store():
    # Look up nearest nodes to ID.
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
    # TODO: STOREs should probably include a small Proof-of-Work

    key = request['data']['key']
    value = (request_data['pubkey'], request['data']['ip'], request['data']['port'])
    kademlia_state['data_store'][key].append(value)

def initialize_dht():
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

    # TODO Random walk on each k bucket further than closest neighbor
    # this should be done asynchronously
    kademlia_do_random_walk(closest_k_bucket)

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
                    response_data += json.dumps(kademlia_find_node(parsed_data, query="node"))
                elif parsed_data['command'] == 'dht_find_value':
                    pass
                elif parsed_data['command'] == 'fetch_file':
                    do_fetch()
                elif parsed_data['command'] == 'add_file':
                    # process file and add to filestore
                    # publish to DHT
                    pass
                elif parsed_data['command'] == 'add_file_to_library':
                    # create metadata record
                    # add to library's merkle root for metadata
                    # save metadata record and announce to dht
                    # ping all connected library nodes to tell them
                    pass
                elif parsed_data['command'] == 'create_library':
                    # create configuration record and metadata merkle root
                    # publish both in the DHT. That's it for the network!
                    # need to upload local state and start Banking and Coordinator if needed
                    pass
                elif parsed_data['command'] == 'add_user_to_library':
                    # update user database, republish to DHT
                    # notify connected nodes
                    pass
                elif parsed_data['command'] == 'send_transaction':
                    # sends a transaction from one address to another. be careful!
                    pass
                elif parsed_data['command'] == 'DEBUG__dht_add':
                    _kademlia_add_node(parsed_data)
                    response_data += 'SUCCESS'

        self.send_response(200)
        self.end_headers()

        if response_data:
            self.wfile.write(response_data.encode('utf-8'))

def shutdown_sockets():
    if tcp_socket:
        # TODO XXX each connection should get a chance to GOAWAY and clean up
        # also need to kill any active UDP activity
        print("Shutting down TCP socket")
        tcp_socket.close()

def shutdown_json_rpc():
    if httpd_instance:
        print("Shutting down JSON-RPC server")
        httpd_instance.shutdown()

def start_json_rpc(port):
    global httpd_instance

    with socketserver.TCPServer(("", port), BiblionRPCRequestHandler) as httpd:
        httpd_instance = httpd
        print("serving at port", port)
        try:
            httpd.serve_forever()
        except:
            print("Exception occurred in HTTP server")
        print("Cleaning up JSON-RPC TCPServer")

    httpd_instance = None
