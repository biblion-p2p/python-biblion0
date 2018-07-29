import json
import base64
import http.server
import socketserver
from datetime import datetime

import client_api.download

from log import log

httpd_instance = None
identity = None

class BiblionRPCRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/rpc':
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Only use /rpc please!\n")
            return

        response_data = ""
        if 'content-length' in self.headers:
            input_length = self.headers.get('content-length')
            input_data = self.rfile.read(int(input_length))
            parsed_data = json.loads(input_data)

            if 'service' in parsed_data:
                serv = identity.services.get_service(parsed_data['service'])
                response_data += serv.handle_rpc(parsed_data['request'])
            elif 'command' in parsed_data:
                if parsed_data['command'] == 'fetch_file':
                    client_api.download.do_fetch(identity, parsed_data)
                    id = parsed_data['id']
                    if not identity.data_store.have_data(id):
                        response_data += "Failed to download file"
                    else:
                        response_data += "ok"
                elif parsed_data['command'] == 'save_file':
                    file_id = parsed_data['id']
                    if not identity.data_store.have_data(file_id):
                        response_data += "File not available. Try fetch_file first."
                    else:
                        client_api.download.do_save_file(identity, file_id, parsed_data['path'])
                        response_data += 'ok'
                elif parsed_data['command'] == 'add_file':
                    file_path = parsed_data['path']
                    # process file and add to filestore
                    file_hash = identity.data_store.process_file(file_path)
                    # TODO XXX for now this code assumes the default global identity
                    # publish to DHT
                    message = {
                        'hash': file_hash,
                        'pubbits': identity.get_public_bits().decode('utf-8'),
                        'addrs': identity.collect_addresses(),
                        'time': round(datetime.utcnow().timestamp())
                    }
                    signature = identity.sign(json.dumps(message, sort_keys=True).encode('utf-8'))
                    signed_message = {'message': message, 'sig': base64.b64encode(signature).decode('utf-8')}
                    log("Processed file %s\n" % signed_message)
                    identity.services.get_service('_global.kademlia').do_store(file_hash, signed_message)
                    response_data += "Added and announced as %s\n" % file_hash
                elif parsed_data['command'] == 'add_file_to_library':
                    # create metadata record
                    # add to library's merkle root for metadata
                    # save metadata record and announce to dht
                    # ping all connected library nodes to tell them
                    pass
                elif parsed_data['command'] == 'create_library':
                    # create configuration record and metadata merkle root
                    # publish both in the DHT. That's it for the network!
                    # need to upload local state and start Banking and Coordinator if needed
                    pass
                elif parsed_data['command'] == 'add_user_to_library':
                    # update user database, republish to DHT
                    # notify connected nodes
                    pass
                elif parsed_data['command'] == 'send_transaction':
                    # sends a transaction from one address to another. be careful!
                    pass
            else:
                response_data += "Please specify service or global command"

        self.send_response(200)
        self.end_headers()

        if response_data:
            self.wfile.write(response_data.encode('utf-8'))

def shutdown_json_rpc():
    if httpd_instance:
        log("Shutting down JSON-RPC server")
        httpd_instance.shutdown()

def start_json_rpc(port, ident):
    global httpd_instance
    global identity
    identity = ident

    with socketserver.TCPServer(("", port), BiblionRPCRequestHandler) as httpd:
        httpd_instance = httpd
        log("JSON-RPC serving at port: %s" % port)
        try:
            httpd.serve_forever()
        except:
            log("Exception occurred in HTTP server")
        log("Cleaning up JSON-RPC TCPServer")

    httpd_instance = None
