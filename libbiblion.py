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

    # over udp
    if mt == 'ping':
        pass
    elif mt == 'hello':
        handle_hello(stream, message['payload'])
    elif mt == 'query_pieces':
        # Request a range of pieces
        # should implement dynamic choke algorithm
        # check out libtorrent. they have a good one for seeding that prefers peers who just started or who are about to finish
        #https://github.com/arvidn/libtorrent/blob/master/src/choker.cpp
        query_pieces(stream, message['payload'])
    elif mt == 'download_piece':
        download_piece(stream, message['payload'])
    elif mt == 'lynx_peer_exchange':
        # Return known peers that have the same content. Useful for swarm management
        pass
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

def do_fetch(fetch_data):
    if fetch_data.get('is_library') and library['has_custom_routing']:
        peers = library.router.get_peers
        if peers.failed:
            global_dht.get_peers
    else:
        peers = kademlia_do_lookup(fetch_data['id'], type="value")

    connected_peers = random.sample(peers, min(10, len(peers))) # we connect to many peers to query their ownership, but will only download from a few

    # TODO: At this point we should announce ourselves to the DHT. Hm, maybe this can be piggybacked on the FINDVALUE?

    for peer in connected_peers:
        # TODO XXX, we should wait for at least 5 peers to respond and choose the ones with the lowest ping. warning: those chosen nodes may have bad pricing!
        peer_id = public_bits_to_peer_id(peer['pubbits'].encode('utf-8'))
        if peer_id in connections:
            conn = connections[peer_id]
        else:
            connect(peer_id, peer['addrs'])
            # TODO XXX verify connection succeeded
            conn = connections[peer_id]
        piece_query = {'type': 'query_pieces',
                       'payload': {'files': [fetch_data['id']]}}
        res = send_request_sync(conn, piece_query)[0]['payload']
        if res['have']:
            log("Peer has data: %s" % res)
            price = res['price']
            if price != 0:
                log("Can't handle micropayment based downloads yet")
                return
            # TODO need to confirm price is correct. to start, we can simply use bits as price, and disconnect from nodes that misbehave
            if False and res['isTorrent']:
                # TODO XXX This whole thing needs work
                # The payment handling should probably wrap the protocol somehow
                p.mark_active(fetch_data.id)
                while p.is_active: # ie, unchoked
                    for pieces in fetch_state.rarest_pieces(p, p.trust):  # get some rare pieces from the node based on their trust. if they behave well, we request more.
                        payment_channel = None
                        if p.is_library_node(fetch_data.library) and library.needs_payment():
                            if p.has_payment_channel(piece):
                                payment_channel = p.payment_channel
                            else:
                                payment_channel = library.create_payment_channel(p, piece, 5)

                        for piece in pieces:  # TODO parallelize based on trust
                            if payment_channel:
                                payment_channel.add_signature(piece)  # bump up the authorized transaction amount. MUST BE THREAD SAFE!
                            p.get_block(piece, payment_channel)
                            p.trust += 1  # increase outstanding requests
                            if p.newly_choked:
                                p.abort_download  # wait for existing stuff to stop, then choose new peer

                        p.request_piece(piece, payment_channel)
            else:
                preq = {'type': 'download_piece',
                        'payload': {'id': fetch_data['id']}}
                pres = send_request_sync(conn, preq)[0]['payload']

                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(pres['data'].encode('utf-8'))
                hash = digest.finalize().hex()

                if hash != fetch_data['id']:
                    log("Transferred data was incorrect!")
                    raise

                tmpfile = open('/tmp/bibtemp', 'w')
                tmpfile.write(pres['data'])
                tmpfile.close()

                process_file('/tmp/bibtemp')
                # TODO XXX need to make sure we also announce to DHT. See above as well, for torrent downloads
        else:
            # mark the node as unneeded. it can be pruned or kept active for gossip, etc
            # should send goaway if truly unneeded
            p.mark_as_unneeded()


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

def _util_nodeid_to_bits(peer_id):
    peer_id_bytes = base64.b64decode(peer_id)
    return _util_convert_bytestring_to_bits(peer_id_bytes)

def _util_convert_bytestring_to_bits(bytes):
    # this function shouldn't be needed in the rust version. we can just bit-twiddle in the trie
    result = ""
    for byte in bytes:
        current_byte = ""
        for n in range(8):
            bit = (byte >> n) & 1
            current_byte = "01"[bit] + current_byte
        result += current_byte
    return result
