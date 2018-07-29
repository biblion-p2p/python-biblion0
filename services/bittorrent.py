
class BitTorrent(object):
    def __init__(self, library):
        self.library = library

    def get_name(self):
        return "bittorrent"

    def start(self):
        pass

# just scratch work right now
if False:
    if mt == 'download_piece':
        download_piece(stream, message['payload'])
    elif mt == 'peer_exchange':
        # Return known peers that have the same content. Useful for swarm management
        pass

    def get_name(self):
        return "bittorrent"

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
