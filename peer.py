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

from libbiblion import send_hello, handle_new_biblion_stream
from log import log

class WrappedStream(object):
    # XXX unused so far...
    def __init__(self, stream):
        self.stream = stream

    def send_response(self, message):
        # Sends an object over the stream and closes the stream.
        self.stream.send

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
        self.active_streams = {}

    def add_transport(*whatever):
        # XXX doesn't do anything for now....
        # It would be convenient if peers could get easy access to their
        #  "connection" from connection oriented transports
        pass

    def send_request(self):
        # Sends a request asynchronously
        pass

    def send_message(self):
        # Send a lone message. Useful for notifications
        pass

    def send_request_sync(self, protocol, request):
        # Sends a request and waits for a response from the remote peer.
        # Create a stream context with a protocol and library information
        # These will be used to initialize the stream
        # Send the request in the first packets.
        # Await the response from the other side.

        # TODO XXX applications should be able to request channel type
        #conn = self.connections[0]

        # XXX this is hard coded and should be removed
        conn = self.identity.transports['tcp']

        stream = conn.create_stream(self.peer_id, protocol, 0)  # , library)
        stream.send_message(request)
        while stream.open:
            stream.event.wait()
            stream.event.clear()
        return stream.data

    def on_ready(self):
        # hmmm....
        # unused for now. maybe this should be required?
        send_hello(self)

    def handle_goaway(self):
        # The peer can tell us to GOAWAY, which means they are going offline.
        # Applications need to cleanup, channels need to be closed, and this peer
        # should be marked as inactive
        pass

    def handle_new_stream(self, stream):
        # TODO XXX this needs to be pluggable. We should route based on application
        gevent.spawn(handle_new_biblion_stream, stream)

    def reserve_channel(self, reliable=True):
        """
        This should make an effort to establish a communications channel with
        the remote peer that satisfies the given constraints.
        """

        # for transport in self.identity.transports:
        #     if transport['is_reliable']:
        #         if not transport.is_ready(peer_id):
        #             #transport.become_ready(peer)
        #             transport.connect(peer)
        #             transport.mark_needed()

        # XXX Defaulting to TCP for now. We should only connect if we don't already have a channel available
        tcp_transport = self.identity.transports['tcp']
        if not tcp_transport.is_ready(self):
            tcp_transport.become_ready(self)

    def release_channel(self, reliable=True):
        """
        Releases a channel that we previously reserved. Any connections MAY
        remain open, but it is not guaranteed.
        """
        pass
