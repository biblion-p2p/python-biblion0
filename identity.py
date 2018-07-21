import base64
import json
import socket
import random
import struct

import gevent

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from log import log
from peer import Peer

class Identity(object):
    """
    An identity is a represented by an asymmetric keypair.
    Each identity listens for connections from other peers.
    A node might have multiple active peer pools. These peer pools might have
    some of the same peers, but they will all communicate over separate
    channels.
    """

    __slots__ = ['public_key', 'private_key', 'addresses', 'peers']

    def __init__(self, keypair, addresses):
        self.public_key, self.private_key = keypair
        self.addresses = addresses
        self.peers = {}

    def pub_to_nodeid(self, pubkey):
        pub_bits = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return self.pubbits_to_nodeid(pub_bits)

    def pubbits_to_nodeid(self, pubbits):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(pubbits)
        return base64.b64encode(digest.finalize()).decode("utf-8")

    def get_pubbits(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def add_or_update_peer(self, peer_id, addrs=None):
        """
        Adds a record of a peer
        """
        if peer_id not in self.peers:
            peer = Peer(peer_id, addrs, self)
            self.peers[peer_id] = peer
        return self.peers[peer_id]

    # XXX TODO XXX the below functions are duplicated in Peer and need to be in a TCP class or something
    def encode_message(self, data):
        if type(data) == str:
            data = data.encode('utf-8')
        length = len(data)
        encoded_length = struct.pack('I', length)
        return encoded_length + data

    def _recv_message(self, sock):
        encoded_length = sock.recv(4)
        length = struct.unpack('I', encoded_length)[0]
        return sock.recv(length)

    # TODO XXX We should also support uTP streams at some point. QUIC looks great. Supports transport-layer multiplexing
    # Also check out UDP over ipv6, including with IPsec.
    def _udp_listen(port):
        # UDP messages can come from anyone at any time. We need to
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", port))

            log("Now listening on UDP socket %s" % port)

            while True:
                # should probably set message state and include address or some shit
                # that way we can check "connection" info even on a connectionless basis
                (message, _, _, address) = sock.recvmsg(65536)
                # TODO XXX need to generate conn context
                # TODO XXX need to figure out how auth cookies will work with this...
                # per application or nah? And should they be per address?
                # TODO XXX UDP messages should include a signed record with the public key and some addresses
                # We should also use the requesters address as an address on the Peer object, so that we can send the
                # response through the port that the client opened up. This let's us quickly handle requests even for
                # nodes behind NAT.
                # It can be a pseudo connection, but it needs to have the context of how to reply to the message
                handle_message(conn, message)

    def _tcp_listen(self, port):
        # XXX Listening on ipv6 should help remove NAT troubles, but it probably isn't widely supported
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            tcp_socket = sock
            sock.bind(("127.0.0.1", port))
            sock.listen(50)

            log("Now listening on TCP socket %s" % port)

            while True:
                conn, _ = sock.accept()
                log("Accepting new connection")
                gevent.spawn(self._handle_tcp_connection, conn)
                gevent.sleep(0)

    def _handle_tcp_connection(self, client_socket):
        """
        Listener-side of TCP crypto handshake
        THIS SHOULD BE REPLACED BY TLS
        """
        # Request 1: local public key, challenge
        req = self._recv_message(client_socket)
        message = json.loads(req)
        nonce_challenge = message['nonce']

        # Response 1: challenge answer, foreign public key, new challenge
        node_pubkey = serialization.load_pem_public_key(message['pub'].encode('utf-8'),
                                                        default_backend())
        nonce = random.randint(0, (2**32)-1)
        signature = self.private_key.sign(struct.pack('I', nonce_challenge),
                                     ec.ECDSA(hashes.SHA256()))
        resp = json.dumps({'pub': self.get_pubbits().decode('utf-8'),
                           'nonce': nonce,
                           'sig': base64.b64encode(signature).decode('utf-8')})
        client_socket.sendall(self.encode_message(resp))

        # Request 2: new challenge answer
        req2 = self._recv_message(client_socket)
        message2 = json.loads(req2)
        try:
            node_pubkey.verify(base64.b64decode(message2['sig']),
                               struct.pack('I', nonce),
                               ec.ECDSA(hashes.SHA256()))
        except:
            log("Signature of other node could not be verified")
            raise

        # End: ECDH
        shared_key = self.private_key.exchange(ec.ECDH(), node_pubkey)

        # Create new Peer record
        peer_id = self.pub_to_nodeid(node_pubkey)
        peer = self.add_or_update_peer(peer_id)
        log("Accepted peer connection from %s" % peer_id)
        peer.attach_tcp_transport(client_socket, shared_key, listener=True)

    def collect_addresses(self):
        return self.addresses

    def collect_protocols(self):
        # XXX TODO actually check what libraries we are a member of.
        return {'_global': ['dht']}
