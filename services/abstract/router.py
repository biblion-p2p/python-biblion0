class Router(object):
    """
    Abstract router. Publishes possession of information, and allows future retrieval
    """

    def announce(self, key, value):
        """
        Announces a key-value pair to the router
        """
        raise

    def find(self, key):
        """
        Retrieves a value from the givent key
        """
        raise
