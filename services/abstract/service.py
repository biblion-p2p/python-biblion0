class Service(object):
    """
    A Service is something that can send and receive messages to other peers.
    A Service and create and respond to streams, and can access data from the
    data store as needed. They can also maintain their own state.
    """

    def __init__(self):
        pass

    def get_name(self):
        """
        Returns a friendly name for this service
        """
        pass

    def get_service_id(self):
        """
        Returns the identifier that should be used to mark streams as
        belonging to this service.
        """
        pass

    def start(self):
        """
        Initialize data as needed. Can connect to other nodes or spawn
        new greenlets to establish persistent activity.
        """
        pass

    def handle_rpc(self, request):
        """
        Handle an RPC command from a local client
        """
        pass

    def handle_message(self, stream):
        """
        Handles a new stream.
        """
        pass
