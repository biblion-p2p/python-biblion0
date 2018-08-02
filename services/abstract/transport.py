class Transport(object):
    """
    Abstract transport. Implements a network path for peers to create Channels
    on which Streams can travel.
    """

    def __init__(self, on_stream, on_connect):
        self.on_connect = on_connect or (lambda x: x)
        self.on_stream = on_stream or (lambda x: x)

    def create_stream(self):
        pass

    def send_message(self):
        pass

    def is_ready(self, peer):
        pass

    def become_ready(self, peer):
        pass

    def listen(self):
        pass

    def shutdown(self):
        pass

    def mark_unneeded(self, peer_id):
        """
        Marks the transport as unneeded. We can clean up the connection state and
        close the connection if needed. We should also keep track of which connections
        haven't been used in a while and prune them automatically in the case of uncooperative
        applications. There should also be a way for applications to mark a connection as needed
        """
        pass

    def mark_needed(self, peer_id):
        """
        Marks the transport as needed for the given peer_id. We should maintain
        the connection even if nothing happens for a while
        """
        pass
