from gevent.event import Event

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

    def __init__(self, transport, connection, service_id, library_id, peer, stream_id=None):
        self.transport = transport
        self.connection = connection
        self.service_id = service_id
        self.library_id = library_id
        self.peer = peer
        if not stream_id:
            stream_id = connection['next_stream_id']
            connection['next_stream_id'] += 2
        self.stream_id = stream_id

        self._opened = False
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
                      stream.get('libraryId'),
                      peer,
                      stream['streamId'])

    def _get_header(self):
        header = {'serviceId': self.service_id,
                  'streamId': self.stream_id}
        if self.library_id:
            header['libraryId'] = self.library_id
        return header

    def build_stream_header_from_message(self, message):
        return self.build_stream_header(message['serviceId'],
                                        message['streamId'],
                                        message.get('libraryId'))

    def send_message(self, data, close=False):
        message = self._get_header()
        if not self._opened:
            self._opened = True
            message['openStream'] = True
        message['data'] = data
        message['closeStream'] = close
        self.transport.send_message(self.connection, message)

    def read_message(self):
        # XXX don't use this yet... need a better way to manage the Event
        self.event.wait()
        return self.data[0]
