import socket

from log import log

class UDP(object):
    def __init__(self, identity, on_connect, on_stream):
        self.identity = identity
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # TODO XXX We should also support uTP streams at some point. QUIC looks great. Supports transport-layer multiplexing
    # Also check out UDP over ipv6
    def listen(self, address, port):
        self.socket.bind((address, port))
        log("Now listening on UDP socket %s" % port)

    def authenticate(self):
        """
        We need to do a 3-way handshake over UDP as well. We can simiplify things
        by generating an auth cookie that stays valid for 24 hours (or so). We
        can record the cookie and ensure that the peer id matches when they
        connect again. This does NOT provide encryption, but since we only use
        UDP for the DHT for now it should be fine.
        """
        return

    def get_messages(self):
        while True:
            # should probably set message state and include address or some shit
            # that way we can check "connection" info even on a connectionless basis
            (message, _, _, address) = sock.recvmsg(65536)
            # TODO XXX need to generate conn context
            # TODO XXX need to figure out how auth cookies will work with this...
            # per application or nah? And should they be per address?
            # TODO XXX UDP messages should include a signed record with the public key and some addresses
            # We should also use the requesters address as an address on the Peer object, so that we can send the
            # response through the port that the client opened up. This let's us quickly handle requests even for
            # nodes behind NAT.
            # It can be a pseudo connection, but it needs to have the context of how to reply to the message
            handle_message(conn, message)
