import base64
import json
import random
import socket
import ssl
import struct

import gevent
from gevent.event import Event
from gevent.lock import RLock

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from biblion.stream import Stream
from crypto_util import *
from log import log

CHUNK_SIZE = 1024*10

class TCPMuxed(object):
    """
    Handles sending and receiving data over a TCP connection.
    Does a crypto handshake TODO: TLS
    """

    transport_info = {
        'reliable': True,
        'ip-mask': False,
        'encrypted': True
    }

    def __init__(self, identity, on_connect, on_stream):
        self.identity = identity
        self.on_connect = on_connect or (lambda x: x)
        self.on_stream = on_stream or (lambda x: x)

        self._listen_socket = None
        self._is_connecting = {}
        self._connections = {}
        self._active_streams = {}
        self._write_lock = RLock()

        self._ssl_context = self._create_ssl_context()

    def _create_ssl_context(self):
        context = ssl.SSLContext()
        context.verify_mode = ssl.CERT_REQUIRED
        context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384')
        priv, _, pub = self.identity.get_key_locs()
        context.load_cert_chain(certfile=pub, keyfile=priv)
        context.load_verify_locations(cafile="../ca/ca.cer")
        # TODO when upgrading to OpenSSL 1.1.x, we can use context.minimum_version instead
        context.options = ssl.OP_ALL|ssl.OP_NO_SSLv2|ssl.OP_NO_SSLv3|\
                          ssl.OP_NO_TLSv1|ssl.OP_NO_TLSv1_1|\
                          ssl.OP_NO_COMPRESSION| ssl.OP_SINGLE_DH_USE|\
                          ssl.OP_CIPHER_SERVER_PREFERENCE|ssl.OP_SINGLE_ECDH_USE
        return context

    def _encode_message(self, data):
        if type(data) == str:
            data = data.encode('utf-8')
        length = len(data)
        encoded_length = struct.pack('I', length)
        return encoded_length + data

    def _recv_message(self, sock):
        encoded_length = sock.recv(4)
        length = struct.unpack('I', encoded_length)[0]
        msg = sock.recv(length)
        return msg

    def _new_connection(self, connected_socket, peer_id, is_listener):
        new_conn = {
            'peer_id': peer_id,
            'socket': connected_socket,
            'listener': is_listener,
            'next_stream_id': 2 if is_listener else 1
        }
        # TODO we can do a lot more here... For example, we can have a
        # TCP-only metaprotocol that keeps the connection alive. This way
        # we can maintain connections even when there is not much activity.
        # Probably important for gossip protocols.
        self._connections[peer_id] = new_conn
        gevent.spawn(self._listen_for_messages, new_conn, peer_id)

    def _get_sock_peer_id(self, sock):
        peer_cert_data = sock.getpeercert(binary_form=True)
        peer_cert = x509.load_der_x509_certificate(peer_cert_data, default_backend())
        return pub_to_nodeid(peer_cert.public_key())

    def _handle_connection(self, connected_socket):
        peer_id = self._get_sock_peer_id(connected_socket)
        self.on_connect(peer_id, self)
        self._new_connection(connected_socket, peer_id, is_listener=True)

    def _stream_router(self, peer_id, message, conn):
        # TODO XXX need to make sure stream ids have correct parity and are not re-used
        header_len = struct.unpack('I', message[:4])[0]
        header = json.loads(message[4:4+header_len])
        inner_msg = message[4+header_len:]
        stream_id = header['streamId']
        #log("Received header %s" % header)
        if (peer_id, stream_id) in self._active_streams:
            stream = self._active_streams[(peer_id, stream_id)]
            # TODO XXX there is no backpressure here. If the stream reader is
            # stuck, stream.data will grow out of control, eating all our memory
            stream.data += inner_msg
            stream.event.set()
        else:  # new stream
            peer = self.identity.add_or_get_peer(peer_id)
            stream = Stream.from_message(header, self, conn, peer)
            stream.data += inner_msg
            stream.event.set()
            stream.opened = True
            self._active_streams[(peer_id, stream_id)] = stream
            self.on_stream(peer_id, stream)

        if header['closeStream']:
            self._clean_stream(stream)

    def _clean_stream(self, stream):
        stream_id = stream.stream_id
        peer_id = stream.peer.peer_id
        self._active_streams[(peer_id, stream_id)].open = False
        del self._active_streams[(peer_id, stream_id)]

    def _get_header(self, stream):
        header = {'serviceId': stream.service_id,
                  'streamId': stream.stream_id}
        return header

    def _send_message_chunked(self, stream, data, close=False):
        log("Chunking...")
        running_total = 0
        total_length = len(data)
        while running_total < len(data):
            data_piece = data[total:running_total+CHUNK_SIZE]
            if close and running_total+CHUNK_SIZE >= len(data):
                self.send_message(conn, stream, data_piece, close)
            else:
                self.send_message(conn, stream, data_piece)
            running_total += CHUNK_SIZE

    def send_message(self, stream, data, close=False):
        if len(data) > CHUNK_SIZE:
            self._send_message_chunked(stream, data, close=close)
            return
        header = self._get_header(stream)
        if not stream.opened:
            stream.opened = True
            header['openStream'] = True
        header['dataLen'] = len(data)
        header['closeStream'] = close
        if close:
            self._clean_stream(stream)
        enc_header = json.dumps(header).encode('utf-8')
        header_length = len(enc_header)
        encoded_length = struct.pack('I', header_length)
        data = encoded_length + enc_header + data
        self._write(stream.connection, data)

    def _listen_for_messages(self, conn, peer_id):
        while True:
            try:
                message = self._recv_message(conn['socket'])
            except Exception as e:
                log("Connection failed. Closing. %s" % e)
                conn['socket'].close()
                break

            self._stream_router(peer_id, message, conn)
            gevent.sleep(0)  # yield

    def _write(self, conn, data):
        with self._write_lock:
            data = self._encode_message(data)
            #data = self._encode_message(self._sym_encrypt(data, conn['session_key']))
            conn['socket'].sendall(data)
        gevent.sleep(0)

    def create_stream(self, peer_id, service_id):
        if not peer_id in self._connections:
            # TODO establish a connection with the given peer.
            # This means we'll need the TCP addresses of the remote peer. Hm, maybe we should pass in a peer reference instead?
            log("XXX Shouldn't get here for now")
            raise
        peer = self.identity.add_or_get_peer(peer_id)
        conn = self._connections[peer_id]
        new_stream = Stream(self, conn, service_id, peer)
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
        sock = self._ssl_context.wrap_socket(sock, server_side=False)
        # TODO handle connection failure
        sock.connect((address, port))

        received_peer_id = self._get_sock_peer_id(sock)
        if received_peer_id != peer_id:
            log("Wrote peer found in handshake")
            # TODO useful exception
            raise

        self._new_connection(sock, peer_id, is_listener=False)
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
                    ssl_sock = self._ssl_context.wrap_socket(connected_socket, server_side=True)
                except Exception as e:
                    log("Listening socket failed. Shutting down TCP. %s" % e)
                    sock.close()
                    break
                log("Accepting new connection")
                gevent.spawn(self._handle_connection, ssl_sock)
                gevent.sleep(0)

    def shutdown(self):
        if self._listen_socket:
            self._listen_socket.close()
            self._listen_socket = None
        for conn in self._connections.values():
            conn['socket'].close()
