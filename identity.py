import base64
import json
import socket
import random
import struct

import gevent

from crypto_util import *
from log import log
from peer import Peer
from tcp import TCPMuxed
from udp import UDP

class Identity(object):
    """
    An identity is a represented by an asymmetric keypair.
    Each identity listens for connections from other peers.
    """

    __slots__ = ['public_key', 'private_key', 'transports', 'addresses', 'peers']

    def __init__(self, keypair, addresses):
        self.public_key, self.private_key = keypair
        self.addresses = addresses
        self.transports = {}
        self.peers = {}

    def setup_transports(self):
        ipv4_addrs = self.addresses['ipv4']
        if 'tcp' in ipv4_addrs:
            for net in ipv4_addrs['tcp']:
                tcp_transport = TCPMuxed(self, on_connect=self.handle_connection, on_stream=self.handle_new_stream)
                self.transports['tcp'] = tcp_transport
                gevent.spawn(tcp_transport.listen, *net)
        if 'udp' in ipv4_addrs:
            for net in ipv4_addrs['udp']:
                udp_transport = UDP(self, on_connect=self.handle_connection, on_stream=self.handle_new_stream)
                self.transports['udp'] = udp_transport
                gevent.spawn(udp_transport.listen, *net)

    def get_public_bits(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_own_id(self):
        return pub_to_nodeid(self.public_key)

    def add_or_get_peer(self, peer_id, addrs=None):
        """
        Adds a record of a peer
        """
        if peer_id not in self.peers:
            peer = Peer(peer_id, addrs, self)
            self.peers[peer_id] = peer
        return self.peers[peer_id]

    def handle_connection(self, peer_id, transport):
        # Create new Peer record
        peer = self.add_or_get_peer(peer_id)
        log("Accepted peer connection from %s" % peer_id)
        peer.add_transport(transport)

    def handle_new_stream(self, peer_id, stream):
        peer = self.add_or_get_peer(peer_id)
        peer.handle_new_stream(stream)

    def handle_stream(self, peer_id, stream):
        peer = self.add_or_get_peer(peer_id)
        peer.handle_stream(stream)

    def collect_addresses(self):
        return self.addresses

    def collect_protocols(self):
        # XXX TODO actually check what libraries we are a member of.
        return {'_global': ['dht']}
