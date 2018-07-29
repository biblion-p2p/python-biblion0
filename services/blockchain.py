class Blockchain(object):
    """
    A generalized blockchain. Records are apended to a secured
    ledger. Blocks are appended based on a predefined strategy. Every record
    in a block must pass a verification. A block itself must also have a
    verification strategy (eg. PoW). Blockchain state is updated based on
    block gossip, verification, and relying on the longest chain.
    """

    def __init__(self):
        pass

    def _verify_record(self):
        # Verifies a record in a block or heard via gossip
        pass

    def _verify_block(self):
        # Verifies that a block is valid
        pass

    def _update_state(self):
        # Updates local state based on new blocks
        pass

    def _rollback_state(self):
        # Rolls back changes from a block. Necessary in case of forks.
