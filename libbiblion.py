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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from log import log

def handle_new_biblion_stream(stream):
    """
    Temporary generic request handler for biblion.
    Protocol 1 (Though protocol number isn't even used yet, as of this comment).
    Each message has a type and a payload.
    The type should eventually be mostly elevated to the streaming layer, with
    message signaling handled per application.
    """

    message = stream.data.pop()
    mt = message['type']

    log("Received message %s, %s\n" % (stream, message))

    if mt == 'hello':
        handle_hello(stream, message['payload'])
    elif mt == 'query_pieces':
        # Request a range of pieces
        # should implement dynamic choke algorithm
        # check out libtorrent. they have a good one for seeding that prefers peers who just started or who are about to finish
        #https://github.com/arvidn/libtorrent/blob/master/src/choker.cpp
        query_pieces(stream, message['payload'])
    elif mt == 'lynx_send_transaction':
        #
        pass
    elif mt == 'biblion_sync_blockchain':
        # Return what the most recent block number is
        pass
    elif mt == 'biblion_query_price':
        # should specify what we have in a request.
        # response should in include what they have and if they accept our proposal.
        pass
    elif mt == 'biblion_announce_block':
        pass
    elif mt == 'biblion_send_transaction':
        pass

def hello(identity, peer_info):
    peer_id, addrs = peer_info
    peer = identity.add_or_get_peer(peer_id)
    peer.reserve_channel()  # establishes a TCP connection
    send_hello(peer)

def send_hello(peer):
    # message should include our public addresses, our public library memberships, and our services for each library

    message = {'type': 'hello',
               'payload': {
                    # TODO XXX need to get our current peer id for the current connection
                   'addrs': peer.identity.collect_addresses(),
                   'libraries': peer.identity.collect_protocols()
               }}

    response = peer.send_request_sync(1, message)  # TODO XXX protocol 1 is generic Biblion protocol
    response = response[0]['payload']
    log("got HELLO response")

    # TODO process library memberships in response or something
    #peer.addresses = response['addrs']

    #_kademlia_add_node(peer, {'addrs': response['addrs'], 'peer_id': peer.peer_id})

def handle_hello(stream, request):
    # record libraries and services provided by node
    log("Handling HELLO")

    # TODO update the addresses of the peer
    #stream.peer.addrs = request['addrs']
    response = {'type': 'hello',
                'payload': {'addrs': stream.transport.identity.collect_addresses(),
                            'libraries': stream.transport.identity.collect_protocols()}}

    stream.send_message(response, close=True)

    #_kademlia_add_node(stream['peer'], {'addrs': request['addrs'], 'peer_id': stream['peer'].peer_id})

def query_pieces(stream, request):
    result = {'have': [], 'price': 0}
    for f in request['files']:
        if False and f.get('isTorrent'):
            # TODO XXX need to enable torrent downloads later
            for piece in request['pieces']:
                if have_data(piece):
                    pass
        else:
            if have_data(f):
                result['have'].append(f)

    response = {'type': 'query_pieces',
                'payload': result}
    response_obj = copy(stream['header'])
    response_obj['data'] = response
    response_obj['closeStream'] = True
    send_message(stream['conn'], response_obj)

def download_piece(stream, request):
    # TODO This should be wrapped in an authorization context if needed
    piece_id = request['id']
    if not have_data(piece_id):
        # TODO throw useful exception
        raise

    file_data = read_file(piece_id)

    response = {'type': 'download_piece',
                'payload': {'data': file_data}}
    response_obj = copy(stream['header'])
    response_obj['data'] = response
    response_obj['closeStream'] = True
    send_message(stream['conn'], response_obj)
