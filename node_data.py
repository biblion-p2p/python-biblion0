import os
import json

"""
This class should be used for managing what identity's are running on the
current node, and what kind of quotas are in place. It should also manage
where we store data and stuff like that. We won't need this until later.
"""

class NodeConfiguration(object):
    def __init__(self):
        if os.path.exists("data/client_data.json"):
            # TODO load client data
