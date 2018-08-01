import io
import shutil
import base64
import json
import os

import gevent

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from log import log

SAVE_TIMEOUT = 30  # How many seconds between saving partial db
CHUNK_SIZE = 1024

def util_hash_file(file_object):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    while True:
        data = file_object.read(CHUNK_SIZE)
        if not data:
            break
        digest.update(data)
    return digest.finalize()

def hex_to_b64(hex_id):
    return base64.b64encode(bytes.fromhex(hex_id)).decode('utf-8')

def b64_to_hex(b64_id):
    return base64.b64decode(b64_id).hex()

class FileRecord(object):
    def __init__(self, data_store, path, b64_hash, offset, length):
        self.is_complete = offset == length
        # TODO instead, we should save ranges of complete bits
        self.offset = offset
        self.length = length
        self.file_hash = b64_hash
        self.data_store = data_store
        self.file_object = None
        self._file_name = path
        self._last_log = 0

    def open(self):
        try:
            # hmm, this needs to create the file if it doesn't exist
            self.file_object = open(self._file_name, 'r+b')
        except Exception as e:
            log("Failed to open file %s" % e)
            raise

    def write(self, data):
        if not self.file_object:
            log("Attempted to write to unopened File")
            raise
        self.file_object.write(data)
        self.file_object.flush()
        self.offset += len(data)

        if self.offset - self._last_log > 1e7:
            log("Progress: %s" % self.offset)
            self._last_log = self.offset

        self.data_store.partial_files[self.file_hash] = (self.offset, self.length)

    def finalize(self):
        if not self.file_object:
            self.open()
        if self.offset != self.length:
            log("Tried to finalize incomplete file. Download bug?")
            raise
        self.file_object.seek(0)
        raw_hash = util_hash_file(self.file_object)
        b64_hash = base64.b64encode(raw_hash).decode('utf-8')
        if b64_hash != self.file_hash:
            self.invalid = True
            log("Hash didn't match!")
            raise
        self.file_object.close()
        shutil.move(self._file_name, self.data_store.path)
        del self.data_store.partial_files[self.file_hash]
        self.data_store.add_piece_record(self.file_hash, self.length)
        self.is_complete = True

# TODO this should eventually be per-identity.
class DataStore(object):
    def __init__(self, path):
        self.data_store = {}
        self.path = path
        self.partial_files = self._read_partials()
        self.data_permissions = self._read_permissions()
        gevent.spawn(self._periodic_save)

        self._check_files()

    def _check_files(self):
        # TODO verify that all files that we think we own are still there
        # TODO queue DHT announcements for anything that needs it
        files = os.listdir(self.path)
        for f in files:
            if f == "temp":
                # skip over temp folder lol
                continue
            file_path = os.path.join(self.path, f)
            file_length = os.stat(file_path).st_size
            b64_hash = hex_to_b64(f)
            self.add_piece_record(b64_hash, file_length)

    def _read_partials(self):
        try:
            partials = open('partials.db').read()
            return json.loads(partials)
        except Exception as e:
            log("Failed to load partials database. Creating fresh db. %s" % e)
            return {}

    def _read_permissions(self):
        try:
            permissions = open('permissions.db').read()
            return json.loads(permissions)
        except Exception as e:
            log("Failed to load permission database. Creating fresh db. %s" % e)
            return {}

    def __periodic_save(self):
        log("Saving DataStore state")
        serialized_partials = json.dumps(self.partial_files)
        serialized_permissions = json.dumps(self.data_permissions)
        with open('partials.db', 'w') as f:
            f.write(serialized_partials)
        with open('permissions.db', 'w') as f:
            f.write(serialized_permissions)

    def _periodic_save(self):
        while True:
            gevent.sleep(SAVE_TIMEOUT)
            try:
                self.__periodic_save()
            except Exception as e:
                log("Failed to write partials database %s" % e)

    def prune_temporaries(self):
        # Looks in the temporary file store and remove any temporaries that
        # are not actively being used.
        pass

    def have_data(self, hash):
        return hash in self.data_store

    def have_partial(self, hash):
        return hash in self.partial_files

    def add_piece_record(self, hash, length):
        # TODO store path metadata
        self.data_store[hash] = length

    def get_file(self, b64_hash):
        hex_hash = b64_to_hex(b64_hash)
        if self.have_data(b64_hash):
            file_path = "%s%s"%(self.path,hex_hash)
            length = self.data_store[b64_hash]
            return FileRecord(self, file_path, b64_hash, offset=length, length=length)
        elif self.have_partial(b64_hash):
            file_path = "%stemp/%s"%(self.path,hex_hash)
            offset, length = self.partial_files[b64_hash]
            # TODO XXX check if partial file is complete. If so, move to normal file store
            return FileRecord(self, file_path, b64_hash, offset=offset, length=length)
        else:
            log("Missing that data")
            return None

    def remove_file(self, b64_hash):
        if not self.have_data(b64_hash):
            log("Tried to remove non-existant file")
            return
        # TODO make sure file isn't open by a service
        hex_hash = b64_to_hex(b64_hash)
        os.remove(os.path.join(self.path, hex_hash))
        del self.data_store[b64_hash]

    def process_file(self, file_path):
        f = open(file_path, 'rb')
        raw_hash = util_hash_file(f)
        b64_hash = base64.b64encode(raw_hash).decode('utf-8')
        hex_hash = raw_hash.hex()
        if b64_hash in self.data_store:
            log("File already added")
            return b64_hash
        shutil.copyfile(file_path, self.path + hex_hash)
        length = os.stat(file_path).st_size
        self.add_piece_record(b64_hash, length)
        return b64_hash

    def create_file(self, b64_hash, length):
        hex_hash = b64_to_hex(b64_hash)
        temporary_path = self.path + "temp/"
        new_path = "%s%s" % (temporary_path, hex_hash)
        log("Allocating space for new file")
        f = open(new_path, 'wb')
        total_written = 0
        while total_written < length:
            to_write = min(length-total_written, CHUNK_SIZE)
            wr = f.write(b'\x00' * to_write)
            if wr != to_write:
                log("Failed to create temp file")
                raise
            total_written += wr
        fr = FileRecord(self, new_path, b64_hash, offset=0, length=length)
        self.partial_files[b64_hash] = (0, length)
        return fr
