"""
Handle downloading data. Can download files or start a torrent download
"""

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
            if res['isTorrent']:
                # call into torrent library
                pass
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


class SimpleDownload(object):
    def __init__(self, library):
        self.library = library

    def start(self):
        pass

    def get_name(self):
        return "simpledownload"

    def handle_rpc(self, request):
        if request['command'] == 'download':
            self.do_download(request)

    def do_download(self, request):
        file_id = request['file']
        file_record = DataStore.get_file(file_id)
        if not file_record:
            # new download
            pass
        if not file_record['complete']:
            # resume download
            pass
        else:  # just serve the file locally
            pass

    def handle_message(self, stream):
        message = stream.data.pop()
        mt = message['type']

        if mt != 'download':
            # TODO XXX useful exception
            raise

        self.download_piece(message['payload'], stream)

    def download_piece(self, request, stream):
        # TODO This should be wrapped in an authorization context if needed
        piece_id = request['id']
        if not DataStore.have_data(piece_id):
            # TODO throw useful exception
            raise

        file_data = DataStore.read_file(piece_id)

        response = {'type': 'download_piece',
                    'payload': {'data': file_data}}
        response_obj = copy(stream['header'])
        response_obj['data'] = response
        response_obj['closeStream'] = True
        send_message(stream['conn'], response_obj)
