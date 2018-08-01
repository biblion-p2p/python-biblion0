import base64
import json
import time
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from services._ktrie import KTrie
from biblion.peer import JSONRPC

from log import log

KADEMLIA_K = 16  # k-bucket size
KADEMLIA_D = KADEMLIA_K / 2  # number of disjoint paths. Similar to `alpha` in original kademlia paper
KADEMLIA_SIBLENGTH = KADEMLIA_K * 7  # number of entries in the sibling list

# TODO We need to make this more DDoS resistant. Handshaking prevents egregious
# abuse, but we should add rate-limiting.


# XXX maybe put these somewhere more useful? lol
def _util_nodeid_to_bits(peer_id):
    peer_id_bytes = base64.b64decode(peer_id)
    return _util_convert_bytestring_to_bits(peer_id_bytes)

def _util_convert_bytestring_to_bits(bytes):
    # this function shouldn't be needed in the rust version. we can just bit-twiddle in the trie
    result = ""
    for byte in bytes:
        current_byte = ""
        for n in range(8):
            bit = (byte >> n) & 1
            current_byte = "01"[bit] + current_byte
        result += current_byte
    return result


class Kademlia(object):
    def __init__(self, library):
        self.trie = KTrie()
        self.active_nodes = {}
        self.k_buckets = {}
        self.siblings = {'nodes': [], 'max': 0}
        self.record_store = {}
        for i in range(256): self.k_buckets[i] = []

        self.library = library

    def get_name(self):
        return "kademlia"

    def get_service_id(self):
        # TODO XXX uhhh, this should come from somewhere else
        return "%s.%s" % (self.library.name, self.get_name())

    def start(self):
        # initialize DHT
        # call find_node on self, adding neighbors until buckets are full or we run out of nodes to query

        # TODO XXX hmm, when the bootstrap node starts up it will have no one.
        # When a peer connects to it, we need to be sure to notify Kademlia. Or
        # maybe there's a cleaner way?

        log("Starting Kademlia...")

        # Add existing nodes
        peers = self.library.identity.request_peers(10)
        for p in peers:
            p.reserve_channel()  # TODO: should be unreliable channel
            self._add_node(p)

        """
        To join the network, a node u must have a contact to an already
        participating node w. u inserts w into the appropriate k-bucket. u then
        performs a node lookup for its own node ID. Finally, u refreshes all
        k-buckets further away than its closest neighbor. During the refreshes,
        u both populates its own k-buckets and inserts itself into other nodes’
        k-buckets as necessary.
        """
        self.do_lookup(self.library.identity.get_own_id())

        # TODO Random walk on each k bucket further than closest neighbor
        # this should be done asynchronously
        self.do_random_walk()

    def handle_message(self, stream):
        rpc_context = JSONRPC(stream.peer, stream)
        message = rpc_context.get_request()
        mt = message['type']
        if mt == 'kademlia_find_node':
            self.find_node(rpc_context, message['payload'], query="node")
        elif mt == 'kademlia_find_value':
            self.find_node(rpc_context, message['payload'], query="value")
        elif mt == 'kademlia_publish':
            self.store(rpc_context, message['payload'])

    def handle_rpc(self, request):
        if request['command'] == 'log_dht':
            response = "Current Kademlia DHT state:\n"
            response += "Our node id: %s\n" % self.library.identity.get_own_id()
            response += json.dumps(str(self.trie))
            response += json.dumps(self.record_store)
            return response
        elif request['command'] == 'publish':
            self.do_store(request['key'], request['value'])
            return "ok"
        elif request['command'] == 'reset_dht':
            pass
        elif request['command'] == 'dht_store':
            pass
        elif request['command'] == 'dht_find_node':
            response_data += json.dumps(self.find_node(request, query="node"))
        elif request['command'] == 'dht_find_value':
            pass
        else:
            # TODO raise error
            return "unknown command"

    def find_node(self, rpc_context, request, query=None):
        """
        Finds the k nearest nodes in our kademlia database
        If we have less than k nodes, we return all of them
        """

        if not query:
            log("FIND query should specify NODE or VALUE")
            return

        peer = rpc_context.peer
        if request['sender']:
            peer.add_addresses(request['sender'])
            self._add_node(peer)

        req_node = request['nodeId']
        if query == 'value' and req_node in self.record_store:
            result = self.record_store.get(req_node)
            return result
        results = self._nearest_nodes(req_node)
        # TODO add signature for UDP response

        rpc_context.send_response({'payload': results})
        return results

    def _ping(self):
        # Get a reference to the peer and force a ping.
        # TODO Should add a command on peer to check if a channel is in `ready` state
        pass

    def _send_request(self, peer):
        # TODO XXX in the future, we will want send messages to service based
        # on protocol numbers that need to be negotiated. But for cases where we
        # don't want to wait a round trip to get protocol number, we can specify
        # the protocol using ProtoRoute. This let's us do 0RTT kademlia requests
        # to known nodes.
        if peer.has_protocols():
            rpc_context.send_request_sync(blah)
        else:
            wrapper = ProtoRoute(blah)
            peer.send_message(wrapper)

    def send_find_node(self, peer_id, recipient_peer_id):
        msg = {'type': 'kademlia_find_node',
               'payload': {'nodeId': peer_id,
                           'sender': self.library.identity.collect_addresses()}}
        log("Sending FIND_NODE to %s" % recipient_peer_id)
        peer = self.library.identity.add_or_get_peer(recipient_peer_id)
        rpc_context = JSONRPC(peer)
        res = rpc_context.send_request_sync(self.get_service_id(), msg)
        return res['payload']
        if False:
            # TODO this is old code. Need to request unreliable channel instead
            # Then the above code will continue to work, but over UDP (or QUIC-unreliable)
            address, port = get_ipv4_address(node)
            send_datagram(msg, address)
            connection.send_request(msg)
            # todo get response or timeout and return
            return []

    def _continue_lookup(self, lookup_id, msg):
        lookup_state = kademlia_lookups[lookup_id]
        # Continue lookup until the k nearest nodes have replied
        # TODO for S/Kademlia, I suppose we have to be smarter about disjoint paths?

    def do_lookup(self, peer_id, type="node"):
        # TODO, this function should be able to handle both FIND_NODE and FIND_VALUE

        # lookup_id = random()
        # kademlia_lookups[lookup_id] = new_lookup_state()
        # callback = lambda msg: kademlia_continue_lookup(lookup_id, msg)

        if type == 'value':
            # TODO XXX when this inevitably fails, we should send_find_value below
            if peer_id in self.record_store:
                return self.record_store[peer_id]

        nearest_nodes = []
        for node in self._nearest_nodes(peer_id):
            nearest_nodes.append(node)
            if len(nearest_nodes) >= KADEMLIA_K:
                break

        # generate address lists for disjoint searches
        dpaths = {}
        for index, node in enumerate(nearest_nodes):
            current_d = index % KADEMLIA_D
            if current_d not in dpaths:
                dpaths[current_d] = []
            dpaths[current_d].append(node)

        # this need to be shared among threads to keep paths disjoint
        # TODO: we should probably have a limiter for IP address to prevent sybil. though a few on same ip is fine
        accessed_nodes = []

        # TODO this assumes the global connection
        own_id = self.library.identity.get_own_id()

        def _xor_with(nid):
            return lambda n: self._node_xor_distance(nid, n['peer_id'])

        for path in dpaths.values():  # greenlet for each
            sorted_path = sorted(path, key=_xor_with(own_id))
            current_node = None
            for node in sorted_path:
                if not node in accessed_nodes:
                    current_node = node
                    break
                if index == KADEMLIA_K:
                    # This dpath is finished
                    break
            if not current_node:
                # done with this dpath.
                break
            accessed_nodes.append(current_node)  # synchronized
            # XXX ah, we need to mark if the node actually responded. Not just if it was queried. That makes things more ugly. sigh...
            new_nodes = self.send_find_node(peer_id, current_node['peer_id'])
            # TODO XXX need to enable this for UDP kademlia
            #if confirm_sig(node):
            #   _kademlia_queue_add(node)

            # TODO XXX I think this is for when this code should support FIND_VALUE
            #if peer_id in new_nodes:
            #    return


            # Don't bother including our own id in the results, in case it's present. This simplifies the queries.
            # We should be STOREing our own announcements anyway, though I guess maybe it doesn't make a difference.
            # Hm, we should definitely be STORE the value if we're among the siblings for the key.
            to_remove = []
            for node in new_nodes:
                if node['peer_id'] == own_id:
                    to_remove.append(node)
            for node in to_remove:
                new_nodes.remove(node)
            path.extend(new_nodes)
            # XXX This needs to loop until the path is exhausted. Doesn't matter for now but will break things XXX

        return sorted(accessed_nodes, key=_xor_with(own_id))[:KADEMLIA_K]

    def do_random_walk(self):
        # For each bucket farther away than the closest populated one, choose a random
        # id in that range and do a lookup on it

        # TODO XXX
        return

        for bucket in sorted(self.k_buckets)[::-1]:
            if self.k_buckets[bucket]:
                closest_bucket = bucket
                break
        else:
            log("No K-buckets populated? Oh no...")
            return

        for i in range(closest_bucket):
            rand_id = generate_random_value_for_bucket(i)
            self.do_lookup(rand_id)

    def announce(self, key, value):
        message = {
            'hash': key,
            'pubbits': self.library.identity.get_public_bits().decode('utf-8'),
            'addrs': value,
            'time': round(datetime.utcnow().timestamp())
        }
        signature = self.library.identity.sign(json.dumps(message, sort_keys=True).encode('utf-8'))
        signed_message = {'message': message, 'sig': base64.b64encode(signature).decode('utf-8')}
        log("Processed file %s\n" % signed_message)
        self.do_store(key, signed_message)

    def do_store(self, key_id, value):
        """
        key_id: Base64 256 bit encoded key of the node or value to be stored
        value: Value to store. Should be a timestamped and signed message
        """
        # Look up nearest nodes to ID.
        nearest_peers = self.do_lookup(key_id)
        # Sends signed store request to each node
        store_request = {'type': 'kademlia_publish',
                         'payload': {'key': key_id, 'value': value}}
        for peer_record in nearest_peers:
            peer = self.library.identity.add_or_get_peer(peer_record['peer_id'], peer_record['addrs'])
            # TODO check for unreliable/fast channel
            rpc_context = JSONRPC(peer)
            rpc_context.send_request_sync(self.get_service_id(), store_request)
            # TODO check result

    def store(self, rpc_context, request):
        """
        Announcements will have to signed and timestamped. This way we can filter out
        outdated information in a reliable verifiable way, and ensure that announcements
        are always authenticated
        """

        # XXX lol update this
        _24_hours_ago = 0

        store_request = request['value']['message']
        if store_request['time'] < _24_hours_ago:
            # Ignore stale STOREs
            log("received stale STORE")
            return

        peer_pubbits = store_request['pubbits'].encode('utf-8')
        peer_pubkey = serialization.load_pem_public_key(peer_pubbits,
                                                        default_backend())
        try:
            peer_pubkey.verify(base64.b64decode(request['value']['sig'].encode('utf-8')),
                               json.dumps(store_request, sort_keys=True).encode('utf-8'),
                               ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            log("received invalid STORE %s" % e)
            log(store_request)
            log(peer_pubbits)
            return

        # TODO: enforce storage limits
        # TODO: eliminate old values if needed
        # TODO: STOREs should probably include a small Proof-of-Work

        key = store_request['hash']
        value = store_request
        if key not in self.record_store:
            self.record_store[key] = []
        self.record_store[key].append(store_request)

        rpc_context.send_response({'payload': True})

    def _nearest_bucket(self, n):
        # Returns the index of the most significant bit in the bytestring
        # Returns None if the bytestring doesn't belong in a bucket (it's the same as our nodeid)
        # XXX We should be able to find the nearest bucket faster using deBrujin sequences
        # http://supertech.csail.mit.edu/papers/debruijn.pdf
        n = n.to_bytes(32, byteorder="big")
        for i, b in enumerate(n):
            e = 7
            while e > 0:
                if (b >> e) & 1:
                    return ((31-i)*8) + e
                e -= 1

    def _nearest_nodes(self, peer_id):
        # keep returning neighbors near n until there are none left
        peer_id_bin = _util_nodeid_to_bits(peer_id)
        # optimization: just return all nodes if less than k. TODO only enable after testing the normal way.
        # if len(kademlia_state['active_nodes']) <= KADEMLIA_K:
        #     return list(kademlia_state['active_nodes'].values())
        return self.trie.get_closest(peer_id_bin, count=KADEMLIA_K)


    def _node_xor_distance(self, node1, node2):
        # expects base64 node ids
        # returns an integer representing the XOR distance
        n1b = base64.b64decode(node1)
        n2b = base64.b64decode(node2)
        xor = [a^b for a, b in zip(n1b, n2b)]
        return int.from_bytes(xor, byteorder="big")


    def _remove_node(self, node):
        # removes the node from its kbucket and from the trie
        if node['is_sibling']:
            self.siblings['nodes'].remove(node)
        elif node['kbucket']:
            # remove it from the kbucket
            pass

        # TODO
        # remove the node from the active nodes list
        # remove the node from the trie


    def _queue_add(self, node):
        # TODO check where this is called and make sure signature is checked where needed
        # TODO Queues a node for addition to our Kademlia state
        # This is needed to ensure we limit lock contention on the trie, etc
        pass


    def _add_node(self, peer):
        """
        When we see a node in a response, we check if we have it in our global datastore by checking a global hashmap.
        If so, we update the node’s last-seen timestamp (using the reference from the hash map). If it’s in a K-bucket, we move it to the front of the k-bucket.
        If not, we check if it belongs in the sibling list. If not, we check its target k-bucket. We verify whether the other nodes in the list are live if needed.
        """
        # TODO XXX make this thread safe
        peer_id = peer.peer_id
        own_id = peer.identity.get_own_id()

        if peer_id == own_id:
            # We don't add ourselves to the DHT. It's unnecessary
            log("Attempted to add self to Kademlia ring. Aborting add.")
            return

        addresses = peer.addresses

        if not addresses:
            log("Peer has no addresses. Not adding to DHT")
            return

        if peer_id in self.active_nodes:
            # TODO should be moved to end of list?
            self.active_nodes[peer_id]['last_seen_timestamp'] = time.time()
            return
        xor_distance_int = self._node_xor_distance(own_id, peer_id)

        new_node = {
            'peer_id': peer_id,
            'peer_id_bin': _util_nodeid_to_bits(peer_id),
            'addrs': addresses,
            'last_seen_timestamp': time.time()
        }

        nearest_bucket_id = self._nearest_bucket(xor_distance_int)
        nearest_bucket = self.k_buckets[nearest_bucket_id]

        if len(self.siblings['nodes']) < KADEMLIA_SIBLENGTH:
            self.siblings['nodes'].append(new_node)
            if xor_distance_int > self.siblings['max']:
                self.siblings['max'] = xor_distance_int
        elif xor_distance_int < self.siblings['max']:
            # XXX O(n) performance sink :(
            # find the max and kick it out into the k buckets
            for node in self.siblings:
                sibling_distance = self._node_xor_distance(own_id, node['peer_id'])
                if s_xor_distance_int == self.siblings['max']:
                    self._remove_node(node)
                    # Queue the node for re-addition. This will place it in the kbuckets
                    self._queue_add(node)
                    self.siblings['nodes'].append(new_node)
                    self.siblings['max'] = xor_distance_int
        elif len(nearest_bucket) < KADEMLIA_K:
            nearest_bucket.append(new_node)
        else:
            least_recently_seen = nearest_bucket[-1]
            alive = kademlia.ping(least_recently_seen)
            if alive:
                # TODO XXX ensure the ping result updated the node in the list if alive
                # K bucket is full. Abort add
                return
            else:
                # TODO XXX ensure the ping result removed the node
                nearest_bucket.append(new_node)  # add the new node

        # TODO add record to peer store if necessary
        # Add the node to the trie
        self.trie.add_node(new_node)
