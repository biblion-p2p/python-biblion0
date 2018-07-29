import random
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from crypto_util import public_bits_to_peer_id

from log import log

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
        res = peer.send_request_sync('_global.biblion', piece_query)[0]['payload']
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
                preq = {'type': 'download',
                        'payload': {'id': fetch_data['id']}}
                pres = peer.send_request_sync('_global.simpledownload', preq)[0]['payload']

                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(pres['data'].encode('utf-8'))
                raw_hash = digest.finalize()
                b64_hash = base64.b64encode(raw_hash).decode('utf-8')

                if b64_hash != fetch_data['id']:
                    log("Transferred data was incorrect!")
                    log(b64_hash)
                    raise

                tmpfile = open('/tmp/bibtemp', 'w')
                tmpfile.write(pres['data'])
                tmpfile.close()

                identity.data_store.process_file('/tmp/bibtemp')
                # TODO XXX need to make sure we also announce to DHT. See above as well, for torrent downloads
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
