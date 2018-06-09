import os
import json

class NodeConfiguration(object):
    """
    Manages state of the node. What libraries are joined. What data is
    possessed. Where that data lives.
    """
    def __init__(self):
        if os.path.exists("data/client_data.json"):
            # TODO load client data
