from services.kademlia import Kademlia
from services.bittorrent import BitTorrent
from services.download import SimpleDownload
from services.libbiblion import Biblion

# TODO:
# Support user databases (gossip, or blockchain)
# Support metadata databases (gossip, or blockchain)
# Support banking/reputation systems (trusted bank, trusted blockchain, or independent blockchain)
# Support advanced blockchain config
# Support alternative routing and trusted usersets and authentication patterns for each
# Support alternative download authorization rules

class Library(object):
    """
    A library is a configuration of a data network.
    """
    def __init__(self, identity, name, owner, routers, downloaders):
        self.name = name
        self.owner = owner
        self.routers = routers
        self.downloaders = downloaders
        self.other = [Biblion]  # Biblion meta-protocol is required

        self.identity = identity

    def create_library(lib_spec, identity):
        name = lib_spec['name']
        owner = lib_spec.get('owner')
        routers = []
        for router in lib_spec.get('routing'):
            if router == 'kademlia':
                routers.append(Kademlia)
            else:
                # TODO dns, auth'd dht, etc
                pass
        downloaders = []
        for downloader in lib_spec.get('download'):
            if downloader == 'bittorrent':
                downloaders.append(BitTorrent)
            elif downloader == 'simple':
                downloaders.append(SimpleDownload)
        # TODO cdn, erasure coding, coordination, etc

        return Library(identity, name, owner, routers, downloaders)

    def start(self):
        # Announces all available items to routing layers
        # Later, this should handle registering with an admin for coordination data as needed
        files = seld.identity.data_store.get_items(library=self)
        for f in files:
            for r in self.routers:
                # XXX this won't work since the service is just a class, not an object
                r.announce(f)

    def get_services(self):
        return self.routers + self.downloaders + self.other
