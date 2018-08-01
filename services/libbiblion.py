import base64
import json
import os
import random
import shutil
import socket
import struct
import time

from copy import copy

import gevent
from gevent.event import Event

from log import log
from biblion.peer import JSONRPC

class Biblion(object):
    def __init__(self, library):
        self.library = library

    def get_name(self):
        return "biblion"

    def get_service_id(self):
        # TODO XXX uhhh, this should come from somewhere else
        return "%s.%s" % (self.library.name, self.get_name())

    def start(self):
        pass

    def handle_message(self, stream):
        """
        Temporary generic request handler for biblion.
        Each message has a type and a payload.
        The type should eventually be mostly elevated to the streaming layer, with
        message signaling handled per application.
        """

        rpc_context = JSONRPC(stream.peer, stream)
        message = rpc_context.get_request()
        mt = message['type']

        if mt == 'hello':
            self.handle_hello(rpc_context, message['payload'])
        elif mt == 'query_pieces':
            # Request a range of pieces
            # should implement dynamic choke algorithm
            # check out libtorrent. they have a good one for seeding that prefers peers who just started or who are about to finish
            #https://github.com/arvidn/libtorrent/blob/master/src/choker.cpp
            self.query_pieces(rpc_context, message['payload'])
        elif mt == 'send_transaction':
            # Should be in blockchain
            pass
        elif mt == 'sync_blockchain':
            # Return what the most recent block number is
            # Should be in gossip...
            pass
        elif mt == 'announce_block':
            # Should be in gossip or blockchain. not sure yet
            pass

    def hello(self, identity, peer_info):
        peer_id, addrs = peer_info
        peer = self.library.identity.add_or_get_peer(peer_id)
        peer.reserve_channel()  # establishes a TCP connection
        self.send_hello(peer)

    def send_hello(self, peer):
        # message should include our public addresses, our public library memberships, and our services for each library

        message = {'type': 'hello',
                   'payload': {
                       'addrs': peer.identity.collect_addresses(),
                       'libraries': peer.identity.collect_protocols()
                   }}

        rpc_context = JSONRPC(peer)
        response = rpc_context.send_request_sync(self.get_service_id(), message)
        response = response['payload']
        # TODO process library memberships in response or something
        #peer.addresses = response['addrs']

    def handle_hello(self, rpc_context, request):
        # record libraries and services provided by node
        log("Handling Hello")

        # TODO update the addresses of the peer
        #stream.peer.addrs = request['addrs']
        response = {'type': 'hello',
                    'payload': {'addrs': self.library.identity.collect_addresses(),
                                'libraries': self.library.identity.collect_protocols()}}

        rpc_context.send_response(response)

    def query_pieces(self, rpc_context, request):
        result = {'have': [], 'lengths': {}, 'price': 0}
        for f in request['files']:
            if False and f.get('isTorrent'):
                # TODO XXX need to enable torrent downloads later
                for piece in request['pieces']:
                    if self.library.identity.data_store.have_data(piece):
                        pass
            else:
                if self.library.identity.data_store.have_data(f):
                    result['have'].append(f)
                    result['lengths'][f] = self.library.identity.data_store.data_store[f]

        response = {'type': 'query_pieces',
                    'payload': result}
        rpc_context.send_response(response)
