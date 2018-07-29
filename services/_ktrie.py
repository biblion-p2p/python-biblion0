# A prefix trie for Kademlia. Only splits nodes at places when a prefix is
# shared. This should be optimized to cache lists of K nodes later.

class KTrieNode(object):
    def __init__(self, children, leaf, count):
        self.children = children
        self.leaf = leaf
        self.count = count

class KTrie(object):
    def __init__(self):
        # TODO use KTrieNode instead
        #self.state = KTrieNode(dict(), None, 0)
        self.state = {'children': {}, 'leaf': None, 'count': 0}

    def remove_node(self, peer_id_bin):
        # Remove a node from the trie

        # TODO XXX None of this code is thread safe lol

        trie_root = self.state

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


    def add_node(self, node_object):
        trie_root = self.state
        peer_id_bin = node_object['peer_id_bin']

        peer_id_index = 0
        current_node = trie_root
        while True:
            if current_node['children']:
                # The node is a branch node, iterate into branch
                while peer_id_index < len(current_node['prefix']) and current_node['prefix'][peer_id_index] == peer_id_bin[peer_id_index]:
                    peer_id_index += 1

                if peer_id_index == len(current_node['prefix']):
                    # the prefix matches. iterate down.
                    current_node['count'] += 1
                    current_node = current_node['children'][peer_id_bin[peer_id_index]]
                else:
                    # new to add new branch here
                    branched_node = {'children': current_node['children'],
                                     'prefix': current_node['prefix'],
                                     'leaf': None,
                                     'count': current_node['count']}
                    current_node['count'] += 1
                    current_node['children'][peer_id_bin[peer_id_index]] = {'leaf': node_object,
                                                                            'children': {},
                                                                            'count': 1}
                    current_node['children'][current_node['prefix'][peer_id_index]] = branched_node
                    current_node['prefix'] = current_node['prefix'][:peer_id_index]  # truncate the prefix to represent the new branch
                    return
            elif current_node['leaf'] and current_node['leaf']['peer_id_bin'] == peer_id_bin:
                # This ID is already in the trie. Give up.
                # TODO Maybe this should be where we update the record and kbuckets? Hmm, probably that should be in other code
                return
            elif current_node['leaf']:
                # We need to branch the trie at this point. We find the first
                # uncommon bitstarting at the current index and then branch at that
                # bit.
                while current_node['leaf']['peer_id_bin'][peer_id_index] == peer_id_bin[peer_id_index]:
                    # This is safe because we check if the node ids are equal above.
                    # There must be a difference in the nodes
                    peer_id_index += 1

                # Move current leaf into branch
                current_node['prefix'] = peer_id_bin[:peer_id_index]
                current_node['children'][current_node['leaf']['peer_id_bin'][peer_id_index]] = {'leaf': current_node['leaf'],
                                                                                                'children': {},
                                                                                                'count': 1}
                current_node['count'] += 1
                current_node['leaf'] = None

                # Add new node as child
                current_node['children'][peer_id_bin[peer_id_index]] =  {'leaf': node_object,
                                                                         'children': {},
                                                                         'count': 1}
                return
            else:  # fresh trie
                current_node['leaf'] = node_object
                current_node['count'] = 1
                return


    def collect_leaves(self, node):
        # in the real implementation this should probably be made iterative
        if node['leaf']:
            return [node['leaf']]
        else:
            return self.collect_leaves(node['children']['0']) + self.collect_leaves(node['children']['1'])

    def get_closest(self, peer_id_bin, count):
        trie_root = self.state
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
            if len(results) == count:
                break

            if current_node['prefix'] not in used_prefixes and len(results) + current_node['count'] <= count:
                # Add all the nodes at this branch of the trie
                results.extend(self.collect_leaves(current_node))
                used_prefixes.append(current_node['prefix'])
                if path:
                    current_node = path.pop()
                    continue
                else:
                    break

            if current_node['children']:
                # The node is a branch node, choose the best branch to iterate to
                branch_bit = peer_id_bin[len(current_node['prefix'])]
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
