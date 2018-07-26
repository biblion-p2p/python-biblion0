
class DataStore(object):
    def __init__(self, path):
        self.data_store = {}
        self.path = path

    def have_data(self, hash):
        global _data_store
        return hash in _data_store

    def add_piece_record(self, hash, length):
        global _data_store
        # TODO store length and path metadata
        _data_store[hash] = True

    def read_file(self, hash):
        global _data_store
        if hash not in _data_store:
            # TODO return a useful exception
            raise
        return open("data/pieces/%s"%hash).read()

    def process_file(self, file_path):
        f = open(file_path, 'rb')
        data = f.read()
        length = len(data)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        hash = digest.finalize().hex()
        shutil.copyfile(file_path, "data/pieces/" + hash)
        add_piece_record(hash, length)
        return hash
