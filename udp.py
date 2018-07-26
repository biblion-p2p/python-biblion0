import socket

from log import log

class UDP(object):
    def __init__(self, identity, on_connect, on_stream):
        self.identity = identity
        self.socket = None
        self.on_connect = on_connect or (lambda x: x)
        self.on_stream = on_stream or (lambda x: x)
        self._pseudo_connections = {}

    def _ping(self, peer_id):
        if peer_id not in self.pseudo_connections:
            # TODO get peer
            pass
        peer = self.pseudo_connections[peer_id]
        self.send_datagram()

    def _pseudo_connect(self, peer):


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


    _signed_id = None
    def _get_signed_id():
        # TODO XXX this isn't used yet. We trade peer information in the HELLO message
        global _signed_id
        if not _signed_id or _signed_id['timestamp'] > _1_hour_ago:
            id = {'peer_id': own_id,
                  'address': {'family': 'ipv4', 'nat': 'open', 'address': get_address(), 'port': get_port()},
                  'timestamp': timestamp_now()}
            json_id = json.dumps(id, sort_keys=True)
            signature = sign(json_id)
            _signed_id = {'id' : id, 'sig': signature}
        # otherwise, generate an object with our address (family, nat, address, port), a timestamp, and a signature
        return _signed_id

    _next_req_id = 1
    def send_datagram(self, peer, is_request=False):
        message['from'] = _get_signed_id()
        if is_request:
            message['req_id'] = _req_id
            _next_req_id += 1
        encoded_message = json.dumps(message, sort_keys=True)
        dsock.sendto(message, (address, port))

    # TODO XXX We should also support uTP streams at some point. QUIC looks great. Supports transport-layer multiplexing
    # Also check out UDP over ipv6
    def listen(self, address, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((address, port))
        log("Now listening on UDP socket %s" % port)

    def create_stream(self, peer_id, service_id, library_id=None):
        if not peer_id in self._pseudo_connections:
            log("XXX Shouldn't get here for now")
            pass
        conn = self._connections[peer_id]
        new_stream = Stream(self, conn, service_id, library_id, stream_id=None)
        self._active_streams[new_stream.stream_id] = new_stream
        return new_stream

    def send_message(self):
        pass

    def is_ready(self, peer):
        return peer in self._pseudo_connections

    def become_ready(self, peer):
