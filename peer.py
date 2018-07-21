import base64
import json
import socket
import random
import struct
from copy import copy

import gevent
from gevent.event import Event

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from libbiblion import send_hello, handle_new_request
from log import log

class Peer(object):
    """
    A peer is another node we are aware of.
    A peer can have reliable and unreliable transports attached.
    A peer has an identity, and on communications with it should be encrypted
    """

    def __init__(self, peer_id, addresses, identity):
        self.peer_id = peer_id
        self.addresses = addresses
        self.identity = identity
        self.connections = []
        self.active_streams = {}

    def set_public_key(self, public_key):
        # TODO verify public key matches peer_id
        return

    # TODO these functions below should be in their own TCP class
    def sym_decrypt(self, message, key):
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(b'\x01', message, None)

    def sym_encrypt(self, message, key):
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(b'\x01', message, None)

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

    def attach_tcp_transport(self, socket, session_key, listener=True):
        new_conn = {
            'type': 'tcp',
            'connected': True,
            'socket': socket,
            'session_key': session_key,  # TODO: this should be associated with the transport
            'listener': listener,
            'next_stream_id': 2 if listener else 1
        }
        self.connections.append(new_conn)
        gevent.spawn(self._listen_for_messages, new_conn)

    def get_channel(self, reliable=True):
        # XXX This should return a channel meets the requirement for the application
        return conn[0]

    def send_message(self, conn, message):
        message = json.dumps(message).encode('utf-8')
        enc_msg = self.encode_message(self.sym_encrypt(message, conn['session_key']))
        conn['socket'].sendall(enc_msg)

    def build_stream_header(self, protocol_id, stream_id, library_id):
        header = {'protocolId': protocol_id, 'streamId': stream_id}
        if library_id:
            header['libraryId'] = library_id
        return header

    def create_stream(self, conn, protocol_id, library_id=None):
        self.active_streams[conn['next_stream_id']] = {'data': [],
                                                       'event': Event(),
                                                       'open': True,
                                                       'peer': self,
                                                       'conn': conn}
        header = self.build_stream_header(protocol_id, conn['next_stream_id'], library_id)
        self.active_streams[conn['next_stream_id']]['header'] = header
        msg_id = conn['next_stream_id']
        conn['next_stream_id'] += 2
        return msg_id

    def send_request_sync(self, protocol, request):
        # Sends a request and waits for a response from the remote peer.
        # Create a stream context with a protocol and library information
        # These will be used to initialize the stream
        # Send the request in the first packets.
        # Await the response from the other side.

        # TODO XXX need to be able to support multiple connections
        conn = self.connections[0]

        stream_id = self.create_stream(conn, protocol)
        message = copy(self.active_streams[stream_id]['header'])
        message['openStream'] = True
        message['data'] = request

        self.send_message(conn, message)

        stream = self.active_streams[stream_id]
        while stream['open']:
            stream['event'].wait()
            stream['event'].clear()

        return stream['data']

    def build_stream_header_from_message(self, message):
        return self.build_stream_header(message['protocolId'],
                                        message['streamId'],
                                        message.get('libraryId'))

    def handle_message(self, conn, message):
        # TODO Streams can have expiration time
        message = json.loads(message)
        inner_msg = message['data']
        stream_id = message['streamId']
        if stream_id in self.active_streams:
            stream = self.active_streams[stream_id]
            stream['data'].append(inner_msg)
            stream['event'].set()
        else:  # new stream
            self.active_streams[stream_id] = {'data': [inner_msg],
                                              'event': Event(),
                                              'open': True,
                                              'conn': conn,
                                              'peer': self,
                                              'header': self.build_stream_header_from_message(message)}
            # TODO XXX this needs to be pluggable
            gevent.spawn(handle_new_request, self.active_streams[stream_id])

        if 'closeStream' in message:
            self.active_streams[stream_id]['open'] = False
            del self.active_streams[stream_id]

    def connect(self):
        # TODO XXX should attempt to connect over known address
        # XXX the below will not work for all nodes!
        tcp_addr = self.addresses['ipv4']['tcp'][0]
        self._tcp_connect(tcp_addr)

    def _tcp_connect(self, address):
        """
        Dialer-side of persistent connection handshake
        """
        address, port = address

        # Connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((address, port))

        # Request 1: local public key, challenge
        nonce = random.randint(0, (2**32)-1)
        req1 = json.dumps({'pub': self.identity.get_pubbits().decode('utf-8'), 'nonce': nonce})
        sock.sendall(self.encode_message(req1))

        # Response 1: challenge answer, foreign public key, new challenge
        message = self._recv_message(sock)
        message = json.loads(message)
        node_pubkey = serialization.load_pem_public_key(message['pub'].encode('utf-8'),
                                                        default_backend())
        nonce_challenge = message['nonce']

        advertised_peer_id = self.identity.pubbits_to_nodeid(message['pub'].encode('utf-8'))
        if advertised_peer_id != self.peer_id:
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
        sock.sendall(self.encode_message(req2))

        # End: ECDH
        # WARNING WARNING the python cryptography library uses ephemeral ecdh,
        # which means it will generate the same shared secret every time!
        # Instead we should be establishing TLS connections between nodes, and
        # using forward secrecy
        shared_key = self.identity.private_key.exchange(ec.ECDH(), node_pubkey)

        log("Successfully connected to %s" % self.identity.pub_to_nodeid(node_pubkey))
        self.attach_tcp_transport(sock, shared_key, listener=False)

        # TODO: this should probably be in a callback
        send_hello(self)

    def _listen_for_messages(self, conn):
        while conn['connected']:
            message = self._recv_message(conn['socket'])
            message = self.sym_decrypt(message, conn['session_key'])
            self.handle_message(conn, message)
        # TODO handle disconnect
