import base64
import json
import random
import socket
import struct

import gevent
from gevent.event import Event

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from biblion.stream import Stream
from crypto_util import *
from log import log


class TCPMuxed(object):
    """
    Handles sending and receiving data over a TCP connection.
    Does a crypto handshake TODO: TLS
    """

    def __init__(self, identity, on_connect, on_stream):
        self.identity = identity
        self.on_connect = on_connect or (lambda x: x)
        self.on_stream = on_stream or (lambda x: x)

        self._listen_socket = None
        self._is_connecting = {}
        self._connections = {}
        self._active_streams = {}

    def _sym_decrypt(self, message, key):
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(b'\x01', message, None)

    def _sym_encrypt(self, message, key):
        # XXX TODO nonce re-use!
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(b'\x01', message, None)

    def _encode_message(self, data):
        if type(data) == str:
            data = data.encode('utf-8')
        length = len(data)
        encoded_length = struct.pack('I', length)
        return encoded_length + data

    def _recv_message(self, sock):
        encoded_length = sock.recv(4)
        length = struct.unpack('I', encoded_length)[0]
        return sock.recv(length)

    def _new_connection(self, connected_socket, peer_id, session_key, is_listener):
        new_conn = {
            'peer_id': peer_id,
            'socket': connected_socket,
            'session_key': session_key,
            'listener': is_listener,
            'next_stream_id': 2 if is_listener else 1
        }
        # TODO we can do a lot more here... For example, we can have a
        # TCP-only metaprotocol that keeps the connection alive. This way
        # we can maintain connections even when there is not much activity.
        # Probably important for gossip protocols.
        self._connections[peer_id] = new_conn
        gevent.spawn(self._listen_for_messages, new_conn, peer_id)

    def _handle_connection(self, connected_socket):
        peer_id, session_key = self._handshake_listener(connected_socket)
        self.on_connect(peer_id, self)
        self._new_connection(connected_socket, peer_id, session_key, is_listener=True)

    def _stream_router(self, peer_id, message, conn):
        # TODO XXX need to make sure stream ids have correct parity and are not re-used

        message = json.loads(message)
        log("Received %s" % message)
        inner_msg = message['data']
        stream_id = message['streamId']
        if (peer_id, stream_id) in self._active_streams:
            stream = self._active_streams[(peer_id, stream_id)]
            stream.data.append(inner_msg)
            stream.event.set()
        else:  # new stream
            peer = self.identity.add_or_get_peer(peer_id)
            stream = Stream.from_message(message, self, conn, peer)
            stream.data.append(inner_msg)
            stream._opened = True
            self._active_streams[(peer_id, stream_id)] = stream
            self.on_stream(peer_id, stream)

        self._clean_stream(message, peer_id)

    def _clean_stream(self, message, peer_id):
        if message.get('closeStream'):
            stream_id = message['streamId']
            self._active_streams[(peer_id, stream_id)].open = False
            del self._active_streams[(peer_id, stream_id)]

    def _listen_for_messages(self, conn, peer_id):
        while True:
            try:
                message = self._recv_message(conn['socket'])
                message = self._sym_decrypt(message, conn['session_key'])
            except Exception as e:
                log("Connection failed. Closing. %s" % e)
                conn['socket'].close()
                break


            self._stream_router(peer_id, message, conn)

    def _handshake_listener(self, client_socket):
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
        signature = self.identity.private_key.sign(struct.pack('I', nonce_challenge),
                                                   ec.ECDSA(hashes.SHA256()))
        resp = json.dumps({'pub': self.identity.get_public_bits().decode('utf-8'),
                           'nonce': nonce,
                           'sig': base64.b64encode(signature).decode('utf-8')})
        client_socket.sendall(self._encode_message(resp))

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
        shared_key = self.identity.private_key.exchange(ec.ECDH(), node_pubkey)

        return pub_to_nodeid(node_pubkey), shared_key

    def _handshake_dialer(self, sock, peer_id):
        """
        Dialer-side of persistent connection handshake
        """
        # Request 1: local public key, challenge
        nonce = random.randint(0, (2**32)-1)
        req1 = json.dumps({'pub': self.identity.get_public_bits().decode('utf-8'), 'nonce': nonce})
        sock.sendall(self._encode_message(req1))

        # Response 1: challenge answer, foreign public key, new challenge
        message = self._recv_message(sock)
        message = json.loads(message)
        node_pubkey = serialization.load_pem_public_key(message['pub'].encode('utf-8'),
                                                        default_backend())
        nonce_challenge = message['nonce']

        advertised_peer_id = public_bits_to_peer_id(message['pub'].encode('utf-8'))
        if advertised_peer_id != peer_id:
            log("Connected node has wrong peer id")
            # TODO XXX raise a useful error
            raise

        try:
            node_pubkey.verify(base64.b64decode(message['sig']),
                               struct.pack('I', nonce),
                               ec.ECDSA(hashes.SHA256()))
        except:
            log("Exception! Signature of other node could not be verified")

        # Request 2: new challenge answer
        signature = self.identity.private_key.sign(struct.pack('I', nonce_challenge),
                                     ec.ECDSA(hashes.SHA256()))
        req2 = json.dumps({'sig': base64.b64encode(signature).decode('utf-8')})
        sock.sendall(self._encode_message(req2))

        # End: ECDH
        # WARNING WARNING the python cryptography library will generate the
        # same shared secret every time!
        # Instead we should be establishing TLS connections between nodes, and
        # using forward secrecy
        shared_key = self.identity.private_key.exchange(ec.ECDH(), node_pubkey)

        log("Successfully connected to %s" % pub_to_nodeid(node_pubkey))
        return shared_key

    def send_message(self, conn, message):
        log("Sending %s" % message)
        self._clean_stream(message, conn['peer_id'])
        message = json.dumps(message).encode('utf-8')
        enc_msg = self._encode_message(self._sym_encrypt(message, conn['session_key']))
        conn['socket'].sendall(enc_msg)

    def create_stream(self, peer_id, service_id, library_id=None):
        if not peer_id in self._connections:
            # TODO establish a connection with the given peer.
            # This means we'll need the TCP addresses of the remote peer. Hm, maybe we should pass in a peer reference instead?
            log("XXX Shouldn't get here for now")
            raise
        peer = self.identity.add_or_get_peer(peer_id)
        conn = self._connections[peer_id]
        new_stream = Stream(self, conn, service_id, library_id, peer)
        self._active_streams[(peer_id, new_stream.stream_id)] = new_stream
        return new_stream

    def mark_unneeded(self, peer_id):
        """
        Marks the transport as unneeded. We can clean up the connection state and
        close the connection if needed. We should also keep track of which connections
        haven't been used in a while and prune them automatically in the case of uncooperative
        applications. There should also be a way for applications to mark a connection as needed
        """
        pass

    def mark_needed(self, peer_id):
        """
        Marks the transport as needed for the given peer_id. We should maintain
        the connection even if nothing happens for a while
        """
        pass

    def is_ready(self, peer):
        """
        Returns True if we have a connection to the peer
        """
        return peer.peer_id in self._connections

    def become_ready(self, peer):
        # TODO This should be used instead of connect(). It can be a generic
        # interface for all transports. Even those that aren't connection-oriented.
        # We'll need to extract the TCP address data from the peer, and connect
        # to it, while verifying the peer id.
        if not self.is_ready(peer):
            if peer.peer_id in self._is_connecting:
                log("Waiting on connect")
                self._is_connecting[peer.peer_id].wait()
            else:
                self._connect(peer)

    def _connect(self, peer):
        peer_id = peer.peer_id
        self._is_connecting[peer_id] = Event()

        # TODO XXX, need to iterate through TCP addresses and try to connect
        address, port = peer.addresses['ipv4']['tcp'][0]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # TODO handle connection failure
        sock.connect((address, port))

        # TODO handle handshake failure
        session_key = self._handshake_dialer(sock, peer_id)
        self._new_connection(sock, peer_id, session_key, is_listener=False)
        self._is_connecting[peer_id].set()

    def listen(self, addr, port):
        # XXX Listening on ipv6 should help remove NAT troubles, but it probably isn't widely supported
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            self._listen_socket = sock
            sock.bind((addr, port))
            sock.listen(50)

            log("Now listening on TCP socket %s" % port)

            while True:
                try:
                    connected_socket, _ = sock.accept()
                except Exception as e:
                    log("Listening socket failed. Shutting down TCP. %s" % e)
                    sock.close()
                    break
                log("Accepting new connection")
                gevent.spawn(self._handle_connection, connected_socket)
                gevent.sleep(0)

    def shutdown(self):
        if self._listen_socket:
            self._listen_socket.close()
            self._listen_socket = None
        for conn in self._connections.values():
            conn['socket'].close()
