
class Bank(object):
    def __init__(self):
        self.bank_state = {}

    def upkeep(self):
        # run on a schedule
        # invalidate expired preauthorizations
        pass

    def handle_request(self, request):
        command = request['type']
        if command == 'send_funds':
            pass
        elif command == 'preauthorize':
            # create a micropayments channel
            pass
        elif command == 'check_preauth':
            pass
        elif command == 'query_balance':
            pass

    def _write_to_journal(self):
        # Write a transaction to a local transaction journal
        pass

    def _update_state(self):
        # For libraries with open state, we can update the published merkle root for the bank state
        # Alternative, we can write the changes to a blockchain.

    def _verify_connections(self):
        pass

    def start(self):
        # this function probably isn't needed but i wanted to write some notes
        # read current bank state
        # need to be able to add transactions if correct
        # need to be able to create payment channels
        # need to be able to update payment channel amounts
        # need to close payment channel on request of recipient
        # need to close payment channel after timeout
        # need to broadcast bank updates to all peers
        pass
