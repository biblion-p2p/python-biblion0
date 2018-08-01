import random
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from biblion.peer import JSONRPC
from crypto_util import public_bits_to_peer_id

from log import log

def do_fetch_pseudo(fetch_data):
    """
    Locate peers with the file using the library's routers,
    Then initialize the downloader to connect to those peers
    """
    library = fetch_data.library
    file_id = fetch_data.file_id
    for router in library.routers:
        peers = router.get_peers(file_id)
        if peers:
            break
    else:
        log("Unable to find peers for download")
        raise

    for downloader in library.downloaders:
        downloader.do_download_pseudo(file_id, peers)

def do_download_pseudo(file_id, peers):
    """
    This code should be in the downloader. Connect to the given
    peers and try to download the file_id. Checks for authorization
    using the library's configured scheme. If authorization is possible
    and expected, we continue. If authorization is impossible or has unexpected
    pricing, etc, then we need to bubble up an error to the user.

    The authorization check can be interactive, if it means the user can confirm
    a dynamic price, or whatever.
    """
    for peer in peers:  # concurrent on ~10 peers
        file_record = peer.query_file(file_id)
        if not file_record.have:
            peers.remove(peer)
            continue
        if library.authorization_scheme:
            # check if we can download file
            # if result is unexpected, bubble error up to user
            auth_context = blah
    good_peers.start_download(auth_context)


def do_fetch(identity, fetch_data):
    if fetch_data.get('is_library') and library['has_custom_routing']:
        peers = library.router.get_peers
        if peers.failed:
            global_dht.get_peers
    else:
        peers = identity.services.get_service('_global.kademlia').do_lookup(fetch_data['id'], type="value")

    # EWWWW
    peers = [identity.add_or_get_peer(public_bits_to_peer_id(p['pubbits'].encode('utf-8'))) for p in peers]
    connected_peers = random.sample(peers, min(10, len(peers))) # we connect to many peers to query their ownership, but will only download from a few

    # TODO: At this point we should announce ourselves to the DHT. Hm, maybe this can be piggybacked on the FINDVALUE?
    for peer in connected_peers:
        # TODO XXX we should have a pluggable api for choosing the best peer out of the ones we connect to. Maybe based on ping or pricing?
        piece_query = {'type': 'query_pieces',
                       'payload': {'files': [fetch_data['id']]}}
        rpc_context = JSONRPC(peer)
        res = rpc_context.send_request_sync('_global.biblion', piece_query)['payload']
        if res['have']:
            log("Peer has data: %s" % res)
            price = res['price']
            if price != 0:
                log("Can't handle micropayment based downloads yet")
                return
            # TODO need to confirm price is correct. to start, we can simply use bits as price, and disconnect from nodes that misbehave
            if False and res['isTorrent']:
                # call into torrent library
                pass
            else:
                # TODO choose the appropriate data service for library
                download_service = identity.services.get_service('_global.simpledownload')
                file_length = res['lengths'][fetch_data['id']]
                download_service.handle_rpc({'command': 'download', 'file': fetch_data['id'], 'length': file_length, 'peer_id': peer.peer_id})
                # TODO verify that file was download correctly
                return
        else:
            # mark the node as unneeded. it can be pruned or kept active for gossip, etc
            # should send goaway if truly unneeded
            p.mark_as_unneeded()

def do_save_file(identity, file_id, path):
    if not identity.data_store.have_data(file_id):
        # TODO raise something useful
        raise
    file_data = identity.data_store.read_file(file_id)
    f = open(path, 'w')
    f.write(file_data)
    f.close()
