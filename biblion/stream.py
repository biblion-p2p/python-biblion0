import json

from gevent.event import Event

from log import log

class Stream(object):
    """
    Represents an active stream. A stream is a set of packets sent over a
    communications channel. A stream can have the following optional attributes:
        - reliable
        - encrypted
    Later, streams will have other features such as masking your IP. These features
    are provided by the channel the stream runs over.
    """

    # TODO Streams should have expiration time

    def __init__(self, transport, connection, service_id, peer, stream_id=None):
        self.transport = transport
        self.connection = connection
        self.service_id = service_id
        self.peer = peer
        if not stream_id:
            stream_id = connection['next_stream_id']
            connection['next_stream_id'] += 2
        self.stream_id = stream_id

        self.opened = False
        self.data = []
        self.open = True
        self.event = Event()

    def from_message(stream, transport, connection, peer):
        """
        Creates a new stream object from a received message. This lets us pick
        the stream from our side.
        """
        return Stream(transport,
                      connection,
                      stream['serviceId'],
                      peer,
                      stream['streamId'])

    def write(self, data, close=False):
        self.transport.send_message(self, data, close)

    def close(self):
        # Mark the stream as closed.
        self.transport.send_message(data=None, close=True)

    def read(self):
        # XXX don't use this yet... need a better way to manage the Event
        self.event.wait()
        return self.data.pop(12345)

    def is_alive(self):
        # TODO return false if not. Used to check if underlying connection failed
        # Maybe this should be part of read()?
        pass
