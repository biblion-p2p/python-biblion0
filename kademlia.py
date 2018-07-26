import json

KADEMLIA_K = 16  # k-bucket size
KADEMLIA_D = KADEMLIA_K / 2  # number of disjoint paths. Similar to `alpha` in original kademlia paper
KADEMLIA_SIBLENGTH = KADEMLIA_K * 7  # number of entries in the sibling list

class KTrieNode(object):
    def __init__(self, children, leaf, count):
        self.children = children
        self.leaf = leaf
        self.count = count

class KTrie(object):
    def __init__(self):
        self.state = KTrieNode(dict(), None, 0)

    def _k_trie_remove_node(peer_id_bin):
        # Remove a node from the trie

        # TODO XXX None of this code is thread safe lol

        trie_root = kademlia_state['trie']

        if trie_root['leaf'] and trie_root['leaf']['peer_id'] != peer_id_bin:
            log("Trie does not have requested node")
            return
        elif not trie_root['leaf'] and not trie_root['children']:
            log("Empty trie")
            return

        peer_id_index = 0
        current_node = trie_root
        last_parent = None
        while current_node['leaf'] is None:
            while peer_id_index < len(current_node['prefix']):
                if current_node['prefix'][peer_id_index] != peer_id_bin[peer_id_index]:
                    log("Node could not be found")
                    return
                peer_id_index += 1
            last_parent = current_node
            current_node['count'] -= 1
            current_node = current_node['children'][peer_id_bin[peer_id_index]]

        if last_parent:
            other_branch = '0' if peer_id_bin[peer_id_index] == '1' else '1'
            old_branch = last_parent['children'][other_branch]
            if old_branch['children']:
                last_parent['children'] = old_branch['children']
                last_parent['prefix'] = old_branch['prefix']
            else:
                last_parent['leaf'] = old_branch['leaf']
                last_parent['children'] = {}
            last_parent['count'] = old_branch['count']
            del old_branch
        else:  # root leaf
            current_node['leaf'] = None
            current_node['count'] = 0


    def _k_trie_add_node(node_object):
        trie_root = kademlia_state['trie']
        peer_id = node_object['peer_id_bin']

        peer_id_index = 0
        current_node = trie_root
        while True:
            if current_node['children']:
                # The node is a branch node, iterate into branch
                while peer_id_index < len(current_node['prefix']) and current_node['prefix'][peer_id_index] == peer_id[peer_id_index]:
                    peer_id_index += 1

                if peer_id_index == len(current_node['prefix']):
                    # the prefix matches. iterate down.
                    current_node['count'] += 1
                    current_node = current_node['children'][peer_id[peer_id_index]]
                else:
                    # new to add new branch here
                    branched_node = {'children': current_node['children'],
                                     'prefix': current_node['prefix'],
                                     'leaf': None,
                                     'count': current_node['count']}
                    current_node['count'] += 1
                    current_node['children'][peer_id[peer_id_index]] = {'leaf': node_object,
                                                                        'children': {},
                                                                        'count': 1}
                    current_node['children'][current_node['prefix'][peer_id_index]] = branched_node
                    current_node['prefix'] = current_node['prefix'][:peer_id_index]  # truncate the prefix to represent the new branch
                    return
            elif current_node['leaf'] and current_node['leaf']['peer_id'] == peer_id:
                # This ID is already in the trie. Give up.
                # TODO Maybe this should be where we update the record and kbuckets? Hmm, probably that should be in other code
                return
            elif current_node['leaf']:
                # We need to branch the trie at this point. We find the first
                # uncommon bitstarting at the current index and then branch at that
                # bit.
                while current_node['leaf']['peer_id'][peer_id_index] == peer_id[peer_id_index]:
                    # This is safe because we check if the node ids are equal above.
                    # There must be a difference in the nodes
                    peer_id_index += 1

                # Move current leaf into branch
                current_node['prefix'] = peer_id[:peer_id_index]
                current_node['children'][current_node['leaf']['peer_id'][peer_id_index]] = {'leaf': current_node['leaf'],
                                                                                            'children': {},
                                                                                            'count': 1}
                current_node['count'] += 1
                current_node['leaf'] = None

                # Add new node as child
                current_node['children'][peer_id[peer_id_index]] =  {'leaf': node_object,
                                                                     'children': {},
                                                                     'count': 1}
                return
            else:  # fresh trie
                current_node['leaf'] = node_object
                current_node['count'] = 1
                return


    def _k_trie_collect_leaves(node):
        # in the real implementation this should probably be made iterative
        if node['leaf']:
            return [node['leaf']]
        else:
            return _k_trie_collect_leaves(node['children']['0']) + _k_trie_collect_leaves(node['children']['1'])

    def _k_trie_get_closest(peer_id):
        trie_root = kademlia_state['trie']
        results = []

        if trie_root['count'] == 0:
            # empty trie. just return
            return results

        if trie_root['leaf']:
            return [trie_root['leaf']]

        path = []
        used_prefixes = []

        current_node = trie_root
        while True:
            if len(results) == KADEMLIA_K:
                break

            if current_node['prefix'] not in used_prefixes and len(results) + current_node['count'] <= KADEMLIA_K:
                # Add all the nodes at this branch of the trie
                results.extend(_k_trie_collect_leaves(current_node))
                used_prefixes.append(current_node['prefix'])
                if path:
                    current_node = path.pop()
                    continue
                else:
                    break

            if current_node['children']:
                # The node is a branch node, choose the best branch to iterate to
                branch_bit = peer_id[len(current_node['prefix'])]
                n_branch_bit = '0' if branch_bit == '1' else '1'
                if current_node['prefix'] + branch_bit not in used_prefixes:
                    next_node = current_node['children'][branch_bit]
                    if next_node['leaf']:
                        results.append(next_node['leaf'])
                        used_prefixes.append(current_node['prefix'] + branch_bit)
                        continue
                    else:  # branch
                        path.append(current_node)
                        current_node = next_node
                elif current_node['prefix'] + n_branch_bit not in used_prefixes:
                    next_node = current_node['children'][n_branch_bit]
                    if next_node['leaf']:
                        results.append(next_node['leaf'])
                        used_prefixes.append(current_node['prefix'] + n_branch_bit)
                        continue
                    else:  # branch
                        path.append(current_node)
                        current_node = next_node
                else:
                    if path:
                        current_node = path.pop()
                    else:
                        break

        return results


class Kademlia(object):
    def __init__(self):
        # TODO Add library options here
        self.trie = KTrie()
        self.active_nodes = {}
        self.k_buckets = {}
        self.siblings = {'nodes': [], 'max': 0}
        self.store = {}
        for i in range(256): self.k_buckets[i] = []

    def start(self):
        # initialize DHT
        # call find_node on self, adding neighbors until buckets are full or we run out of nodes to query

        # Add existing nodes
        _kademlia_add_node(known_nodes)

        """
        To join the network, a node u must have a contact to an already
        participating node w. u inserts w into the appropriate k-bucket. u then
        performs a node lookup for its own node ID. Finally, u refreshes all
        k-buckets further away than its closest neighbor. During the refreshes,
        u both populates its own k-buckets and inserts itself into other nodes’
        k-buckets as necessary.
        """
        kademlia_do_lookup(own_id)

        # TODO Random walk on each k bucket further than closest neighbor
        # this should be done asynchronously
        kademlia_do_random_walk(closest_k_bucket)

    def handle_request(self, request):
        mt = request['type']
        if mt == 'kademlia_find_node':
            kademlia_find_node(stream, message['payload'], query="node")
        elif mt == 'kademlia_find_value':
            kademlia_find_node(stream, message['payload'], query="value")
        elif mt == 'kademlia_publish':
            kademlia_store(stream, message['payload'])

    def kademlia_find_node(stream, request, query=None):
        """
        Finds the k nearest nodes in our kademlia database
        If we have less than k nodes, we return all of them
        """

        if not query:
            log("FIND query should specify NODE or VALUE")
            return

        # TODO XXX enable when using UDP DHT
        # if request.signature.address == message.address:
        #     _kademlia_queue_add(request)
        req_node = request['nodeId']
        if query == 'value' and req_node in data_store:
            result = data_store.get(req_node)
            return result
        results = _kademlia_nearest_nodes(req_node)
        # TODO add signature for UDP response

        # TODO clean this up and make it way fducking easier later
        response_obj = copy(stream['header'])
        response_obj['data'] = {'payload': results}
        response_obj['closeStream'] = True
        send_message(stream['conn'], response_obj)
        return results

    def kademlia_find_value(request):
        """
        Returns the value if we have it, or return the k nearest nodes to the node.
        """
        req_id = request['peer_id']
        if req_id in kademlia_state['data_store']:
            results = kademlia_state['data_store']['req_id']
        else:
            results = _kademlia_nearest_nodes(req_node)
        # TODO make response with signature
        return results

    def _ping(self):
        # Get a reference to the peer and force a ping.
        # TODO Should add a command on peer to check if a channel is in `ready` state
        pass

    def kademlia_send_find_node(peer_id):
        msg = {'type': 'kademlia_find_node',
               'payload': {'nodeId': peer_id}}
        log("Sending FIND_NODE to %s" % peer_id)
        peer = Identity.get_peer(peer_id)
        if peer_id in connections:
            return send_request_sync(connections[peer_id], msg)[0]['payload']
        else:
            # TODO use UDP. This should be abstracted away as far as possible
            address, port = get_ipv4_address(node)
            send_datagram(msg, address)
            connection.send_request(msg)
            # todo get response or timeout and return
            return []

    def _kademlia_continue_lookup(lookup_id, msg):
        lookup_state = kademlia_lookups[lookup_id]
        # Continue lookup until the k nearest nodes have replied
        # TODO for S/Kademlia, I suppose we have to be smarter about disjoint paths?

    def kademlia_do_lookup(peer_id, type="node"):
        # TODO, this function should be able to handle both FIND_NODE and FIND_VALUE

        # lookup_id = random()
        # kademlia_lookups[lookup_id] = new_lookup_state()
        # callback = lambda msg: kademlia_continue_lookup(lookup_id, msg)

        if type == 'value':
            # TODO XXX when this inevitably fails, we should send_find_value below
            if peer_id in kademlia_state['data_store']:
                return kademlia_state['data_store'][peer_id]

        nearest_nodes = []
        for node in _kademlia_nearest_nodes(peer_id):
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
        own_id = self.identity.get_own_id()

        def _xor_with(nid):
            return lambda n: _node_xor_distance(nid, n['peer_id'])

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
            new_nodes = kademlia_send_find_node(current_node['peer_id'])
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

    def kademlia_do_random_walk():
        # For each bucket farther away than the closest populated one, choose a random
        # id in that range and do a lookup on it

        # TODO XXX
        return

        for bucket in sorted(kademlia_state['k_buckets'])[::-1]:
            if kademlia_state['k_buckets'][bucket]:
                closest_bucket = bucket
                break
        else:
            log("No K-buckets populated? Oh no...")
            return

        for i in range(closest_bucket):
            rand_id = generate_random_value_for_bucket(i)
            kademlia_do_lookup(rand_id)


    def kademlia_do_store(key_id, value):
        """
        key_id: Base64 256 bit encoded key of the node or value to be stored
        value: Value to store. Should be a timestamped and signed message
        """
        # Look up nearest nodes to ID.
        nearest_nodes = kademlia_do_lookup(key_id)
        # Sends signed store request to each node
        store_request = {'type': 'kademlia_publish',
                         'payload': {'key': key_id, 'value': value}}
        for node in nearest_nodes:
            if node['peer_id'] in connections:
                conn = connections[node['peer_id']]
                send_request_sync(conn, store_request)
                # TODO check result
            else:
                # TODO need to send udp message and wait for response, getting handshake cookie if necessary
                # Alternatively, connect to node with TCP and send them the STORE as normal
                log("Tried to send STORE to unconnected node")
                pass

    def kademlia_store(stream, request):
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
        except:
            log("received invalid STORE")
            log(store_request)
            log(peer_pubbits)
            return

        # TODO: enforce storage limits
        # TODO: eliminate old values if needed
        # TODO: STOREs should probably include a small Proof-of-Work

        key = store_request['hash']
        value = store_request
        if key not in kademlia_state['data_store']:
            kademlia_state['data_store'][key] = []
        kademlia_state['data_store'][key].append(store_request)

        # TODO clean this up and make it way fducking easier later
        response_obj = copy(stream['header'])
        response_obj['data'] = {'payload': True}
        response_obj['closeStream'] = True
        send_message(stream['conn'], response_obj)

    def _kademlia_nearest_bucket(n):
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

    def _kademlia_nearest_nodes(peer_id):
        # keep returning neighbors near n until there are none left
        peer_id_bin = _util_nodeid_to_bits(peer_id)
        # optimization: just return all nodes if less than k. TODO only enable after testing the normal way.
        # if len(kademlia_state['active_nodes']) <= KADEMLIA_K:
        #     return list(kademlia_state['active_nodes'].values())
        return _k_trie_get_closest(peer_id_bin)


    def _node_xor_distance(node1, node2):
        # expects base64 node ids
        # returns an integer representing the XOR distance
        n1b = base64.b64decode(node1)
        n2b = base64.b64decode(node2)
        xor = [a^b for a, b in zip(n1b, n2b)]
        return int.from_bytes(xor, byteorder="big")


    def _kademlia_remove_node(node):
        # removes the node from its kbucket and from the trie
        if node['is_sibling']:
            kademlia_state['siblings'].remove(node)
        elif node['kbucket']:
            # remove it from the kbucket
            pass

        # TODO
        # remove the node from the active nodes list
        # remove the node from the trie


    def _kademlia_queue_add(node):
        # TODO check where this is called and make sure signature is checked where needed
        # TODO Queues a node for addition to our Kademlia state
        # This is needed to ensure we limit lock contention on the trie, etc
        pass


    def _kademlia_add_node(peer, request):
        """
        When we see a node in a response, we check if we have it in our global datastore by checking a global hashmap.
        If so, we update the node’s last-seen timestamp (using the reference from the hash map). If it’s in a K-bucket, we move it to the front of the k-bucket.
        If not, we check if it belongs in the sibling list. If not, we check its target k-bucket. We verify whether the other nodes in the list are live if needed.
        """
        # TODO XXX make this thread safe
        peer_id = request['peer_id']
        own_id = peer.identity.get_own_id()

        if peer_id == own_id:
            # We don't add ourselves to the DHT. It's unnecessary
            return

        addresses = request['addrs']

        if peer_id in kademlia_state['active_nodes']:
            # TODO should be moved to end of list?
            kademlia_state['active_nodes'][peer_id]['last_seen_timestamp'] = time.time()
            return
        xor_distance_int = _node_xor_distance(own_id, peer_id)

        new_node = {
            'peer_id': peer_id,
            'peer_id_bin': _util_nodeid_to_bits(peer_id),
            'addrs': addresses,
            'last_seen_timestamp': time.time()
        }

        nearest_bucket_id = _kademlia_nearest_bucket(xor_distance_int)
        nearest_bucket = kademlia_state['k_buckets'][nearest_bucket_id]

        if len(kademlia_state['siblings']['nodes']) < KADEMLIA_SIBLENGTH:
            kademlia_state['siblings']['nodes'].append(new_node)
            if xor_distance_int > kademlia_state['siblings']['max']:
                kademlia_state['siblings']['max'] = xor_distance_int
        elif xor_distance_int < kademlia_state['siblings']['max']:
            # XXX O(n) performance sink :(
            # find the max and kick it out into the k buckets
            for node in kademlia_state['siblings']:
                sibling_distance = _node_xor_distance(own_id, node['peer_id'])
                if s_xor_distance_int == kademlia_state['siblings']['max']:
                    _kademlia_remove_node(node)
                    # Queue the node for re-addition. This will place it in the kbuckets
                    _kademlia_queue_add(node)
                    kademlia_state['siblings']['nodes'].append(new_node)
                    kademlia_state['siblings']['max'] = xor_distance_int
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
        _k_trie_add_node(new_node)
