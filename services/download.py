"""
Handle downloading data. Can download files or start a torrent download
"""

class SimpleDownload(object):
    def __init__(self, library):
        self.library = library

    def start(self):
        pass

    def get_name(self):
        return "simpledownload"

    def handle_rpc(self, request):
        if request['command'] == 'download':
            self.do_download(request)

    def do_download(self, request):
        file_id = request['file']
        file_record = DataStore.get_file(file_id)
        if not file_record:
            # new download
            pass
        if not file_record['complete']:
            # resume download
            pass
        else:  # just serve the file locally
            pass

    def handle_message(self, stream):
        message = stream.data.pop()
        mt = message['type']

        if mt != 'download':
            # TODO XXX useful exception
            raise

        self.download_piece(message['payload'], stream)

    def download_piece(self, request, stream):
        # TODO This should be wrapped in an authorization context if needed
        file_id = request['id']
        if not self.library.identity.data_store.have_data(file_id):
            log("Don't have requested file")
            log(file_id)
            log(type(file_id))
            # TODO throw useful exception
            raise

        file_data = self.library.identity.data_store.read_file(file_id)

        response = {'type': 'download',
                    'payload': {'data': file_data}}
        stream.send_message(response, close=True)
