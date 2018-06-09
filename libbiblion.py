import base64
import json
import struct
import socket
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec


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
    global connections

    req = recv_message(client_socket)
    message = json.loads(req)
    node_pubkey = serialization.load_pem_public_key(message['pub'].encode('utf-8'),
                                                    default_backend())
    nonce_challenge = message['nonce']
    nonce = random.randint(0, (2**32)-1)
    signature = private_key.sign(struct.pack('I', nonce_challenge), ec.ECDSA(hashes.SHA256()))
    resp = json.dumps({'pub': get_pubbits().decode('utf-8'),
                       'nonce': nonce,
                       'sig': base64.b64encode(signature).decode('utf-8')})
    client_socket.sendall(encode_message(resp))
    req2 = recv_message(client_socket)
    message2 = json.loads(req2)
    if not node_pubkey.verify(base64.b64decode(message2['sig']),
                              struct.pack('I', nonce),
                              ec.ECDSA(hashes.SHA256())):
        print("Signature of other node could not be verified")
    shared_key = private_key.exchange(ec.ECDH(), node_pubkey)

    print ("CONNECTION ESTABLISHED", shared_key)

    connections.append([node_pubkey, shared_key, client_socket])

def connect(node):
    global connections

    # WARNING: This can be MITM'd. The public key/id should be known before
    # connecting. This can be derived from the DHT list (or hardcoded for the bootstrap node(s))
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    print(node)
    sock.connect(node)
    nonce = random.randint(0, (2**32)-1)
    req1 = json.dumps({'pub': get_pubbits().decode('utf-8'), 'nonce': nonce})
    sock.sendall(encode_message(req1))
    message = recv_message(sock)
    message = json.loads(message)
    node_pubkey = serialization.load_pem_public_key(message['pub'].encode('utf-8'),
                                                    default_backend())
    nonce_challenge = message['nonce']
    if not node_pubkey.verify(base64.b64decode(message['sig']), struct.pack('I', nonce), ec.ECDSA(hashes.SHA256())):
        print("Signature of other node could not be verified")
    signature = private_key.sign(struct.pack('I', nonce_challenge), ec.ECDSA(hashes.SHA256()))
    req2 = json.dumps({'sig': base64.b64encode(signature).decode('utf-8')})
    sock.sendall(encode_message(req2))
    # ecdh
    # WARNING WARNING the python cryptography library uses ephemeral ECDH (ECDHE),
    # which means it will generate the same shared secret every time!
    # Instead we should be establishing TLS connections between nodes
    shared_key = private_key.exchange(ec.ECDH(), node_pubkey)

    print ("CONNECTION ESTABLISHED", shared_key)

    connections.append([node_pubkey, shared_key, sock])


def generate_request(command, data):
    pass

def initialize_dht(socket):
    # initialize global DHT
    # call find_node on self, adding neighbors until buckets are full or we run out of nodes to query
    pass
