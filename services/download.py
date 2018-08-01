"""
Simple file transfer service. Supports download from an offset.
"""
import json

from log import log

CHUNK_SIZE = 1024*10

class SimpleDownload(object):
    def __init__(self, library):
        self.library = library
        self.data_store = library.identity.data_store

    def start(self):
        pass

    def get_name(self):
        return "simpledownload"

    def get_service_id(self):
        # TODO XXX uhhh, this should come from somewhere else
        return "%s.%s" % (self.library.name, self.get_name())

    def handle_rpc(self, request):
        log("SimpleDownload received RPC: %s" % request)
        if request['command'] != 'download':
            # TODO XXX useful exception
            log("Unknown command sent to downloader")
            raise
        self._do_download(request)

    def handle_message(self, stream):
        message = stream.read()
        message = json.loads(message)
        if message['type'] != 'download':
            # TODO XXX useful exception
            log("Unknown request sent to downloader")
            raise
        self._handle_download(message['payload'], stream)

    def _do_download(self, request):
        file_id = request['file']
        file_record = self.data_store.get_file(file_id)
        if file_record and file_record.is_complete:
            # already downloaded
            return file_record
        elif not file_record:
            # new download
            file_record = self.data_store.create_file(file_id, request['length'])
            offset = 0
        else:
            # resume download
            offset = file_record.offset

        peer_id = request['peer_id']
        peer = self.library.identity.add_or_get_peer(peer_id)
        file_record.open()
        file_record.file_object.seek(file_record.offset)
        request = {'type': 'download', 'payload': {'id': file_id, 'offset': offset}}
        enc_request = json.dumps(request).encode('utf-8')
        log("Starting transfer")
        stream = peer.send_message(self.get_service_id(), enc_request)
        while stream.open or stream.data:
            data = stream.read()
            file_record.write(data)
        file_record.finalize()
        return file_record

    def _handle_download(self, request, stream):
        # TODO This should be wrapped in an authorization context if needed
        file_id = request['id']
        if not self.data_store.have_data(file_id):
            log("Don't have requested file")
            # TODO throw useful exception
            raise

        file = self.data_store.get_file(file_id)
        file.open()
        file.file_object.seek(request['offset'])
        log("Starting transfer")
        while True:
            file_contents = file.file_object.read(CHUNK_SIZE)
            if not file_contents:  # eof
                stream.close()
                break
            stream.write(file_contents)
