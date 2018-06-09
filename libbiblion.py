import json
import struct
import socket



# node commands:
# ping
# kademlia_find_node
# kademlia_find_data
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
# intiialize_dht

public_key = None
private_key = None
connections = []

def libbiblion_init(pubkey, privkey):
    public_key = pubkey
    private_key = privkey

def encode_message(data):
    length = len(data)
    encoded_legnth = struct.pack('I', length)
    return encoded_legnth + data

def recv_message(socket):
    encoded_length = socket.recv(4)
    length = struct.unpack('I', message_length)
    return socket.recv(length)

def handle_connection(client_socket):
    req = recv_message(socket)
    message = json.loads(req)
    node_pubkey = message['pub']

def connect(node):
    # WARNING: This can be MITM'd. The public key/id should be known before
    # connecting. This can be derived from the DHT list (or hardcoded for the bootstrap node(s))
    socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    nonce = random.randint(0, (2**32)-1)
    req1 = json.dumps({'pub': public_key, 'nonce': nonce})
    socket.sendall(encode_message(req1))
    message = recv_message(socket)
    message = json.loads(message)
    node_pubkey = serialization.load_pem_public_key(message['pub'],
                                                    default_backend())
    nonce_challenge = message['nonce']
    if not node_pubkey.verify(message['sig'], data, ec.ECDSA(hashes.SHA256())):
        print("Signature of other node could not be verified")
    signature = private_key.sign(nonce_challenge, ec.ECDSA(hashes.SHA256()))
    req2 = json.dumps({'sig': signature})
    socket.sendall(encode_message(req2))
    # ecdh
    # WARNING WARNING the python cryptography library uses ephemeral ECDH (ECDHE),
    # which means it will generate the same shared secret every time!
    # Instead we should be establishing TLS connections between nodes
    shared_key = private_key.exchange(ec.ECDH(), node_pubkey)

    connections.append([node_pubkey, shared_key, socket])


def generate_request(command, data):
    pass

def initialize_dht(socket):
    # initialize global DHT
    # call find_node on self, adding neighbors until buckets are full or we run out of nodes to query
    pass
