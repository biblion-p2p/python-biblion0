import base64
import json
import socket
import random
import struct

import gevent

from crypto_util import *
from log import log
from biblion.peer import Peer
from biblion.services import ServiceManager
from biblion.datastore import DataStore
from net.tcp import TCPMuxed
from net.udp import UDP

class Identity(object):
    """
    An identity is a represented by an asymmetric keypair.
    Each identity listens for connections from other peers.
    """

    def __init__(self, keypair, addresses):
        self.public_key, self.private_key = keypair
        self.addresses = addresses
        self.libraries = {}
        self.transports = {}
        self.peers = {}
        self.data_store = DataStore("data/pieces")
        self.services = ServiceManager(self)

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
        if peer_id == self.get_own_id():
            # Can't be a peer to ourselves. Services would get confused
            # XXX raise a useful exception
            raise

        if peer_id not in self.peers:
            peer = Peer(peer_id, addrs, self)
            self.peers[peer_id] = peer
        return self.peers[peer_id]

    def request_peers(self, count):
        """
        Try to return the given number of peers, or all known peers if we
        don't have enough
        """
        if len(self.peers) <= count:
            return self.peers.values()
        else:
            return random.sample(self.peers.values(), count)

    def register_library(self, library):
        """
        Associates us with a library. Does not check to see if we're a legitimate member!
        That will be done by the services.
        """
        self.libraries[library.name] = library
        for serv in library.get_services():
            serv_inst = serv(library)
            service_id = "%s.%s" % (library.name, serv_inst.get_name())
            self.services.register_service(service_id, serv_inst)

    def start_libraries(self):
        self.services.start_all()

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
