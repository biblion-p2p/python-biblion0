import base64
import json
import socket
import random
import struct
from copy import copy

import gevent
from gevent.event import Event

from log import log

class JSONRPC(object):
    def __init__(self, peer, stream=None):
        self.peer = peer
        if stream:
            self.stream = stream

    def send_request_sync(self, service_id, request):
        # Sends a request and waits for a response from the remote peer.
        # Create a stream context with a protocol and library information
        # These will be used to initialize the stream
        # Send the request in the first packets.
        # Await the response from the other side.
        enc_request = json.dumps(request).encode('utf-8')
        log("Sending JSON request: %s" % enc_request)
        stream = self.peer.send_message(service_id, enc_request)
        while stream.open:
            stream.event.wait()
            stream.event.clear()
        resp = stream.data.pop()
        log("Received JSON response: %s" % resp)
        return json.loads(resp)

    def send_response(self, message):
        # Sends an object over the stream and closes the stream.
        resp = json.dumps(message).encode('utf-8')
        log("Sending JSON response %s" % resp)
        self.stream.write(resp, close=True)

    def get_request(self):
        if not self.stream:
            raise
        req = self.stream.data.pop()
        req = json.loads(req)
        log("Received JSON request: %s" % req)
        return req

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

    def add_addresses(self, addrs):
        # TODO XXX this should do a union
        self.addresses = addrs

    def add_transport(*whatever):
        # XXX doesn't do anything for now....
        # It would be convenient if peers could get easy access to their
        #  "connection" from connection oriented transports
        pass

    def send_message(self, service_id, message, close=False):
        # Sends a message to the service on the remote peer. Opens a new stream.
        # XXX this transport is hard coded and should be removed
        transport = self.identity.transports['tcp']
        stream = transport.create_stream(self.peer_id, service_id)
        stream.write(message, close)
        return stream

    def on_ready(self):
        # need to figure out when to call "hello"
        if not self.addresses:
            send_hello(self)

    def handle_goaway(self):
        # The peer can tell us to GOAWAY, which means they are going offline.
        # Applications need to cleanup, channels need to be closed, and this peer
        # should be marked as inactive
        pass

    def handle_new_stream(self, stream):
        gevent.spawn(self.identity.services.route_stream, stream)

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
