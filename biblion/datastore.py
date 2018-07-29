import shutil
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class DataStore(object):
    def __init__(self, path):
        self.data_store = {}
        self.path = path

        # TODO verify that all files that we think we own are still there
        # TODO queue DHT announcements for anything that needs it

    def have_data(self, hash):
        return hash in self.data_store

    def add_piece_record(self, hash, length):
        # TODO store length and path metadata
        self.data_store[hash] = True

    def read_file(self, hash):
        if not self.have_data(hash):
            # TODO return a useful exception
            log("Missing that data")
            raise
        hex_hash = base64.b64decode(hash).hex()
        return open("%s%s"%(self.path,hex_hash)).read()

    def process_file(self, file_path):
        f = open(file_path, 'rb')
        data = f.read()
        length = len(data)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        raw_hash = digest.finalize()
        b64hash = base64.b64encode(raw_hash).decode('utf-8')
        shutil.copyfile(file_path, self.path + raw_hash.hex())
        self.add_piece_record(b64hash, length)
        return b64hash
