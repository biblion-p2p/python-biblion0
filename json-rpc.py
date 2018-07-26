import http.server
import socketserver

httpd_instance = None

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

            if 'command' in parsed_data:
                if parsed_data['command'] == 'log_dht':
                    response_data += "Current Kademlia DHT state:\n"
                    response_data += "Our node id: %s\n" % identity.get_node_id()
                    response_data += json.dumps(kademlia_state)
                elif parsed_data['command'] == 'reset_dht':
                    pass
                elif parsed_data['command'] == 'dht_store':
                    pass
                elif parsed_data['command'] == 'dht_find_node':
                    response_data += json.dumps(kademlia_find_node(parsed_data, query="node"))
                elif parsed_data['command'] == 'dht_find_value':
                    pass
                elif parsed_data['command'] == 'fetch_file':
                    do_fetch(parsed_data)
                    id = parsed_data['id']
                    if not have_data(id):
                        response_data += "Failed to download file"
                    else:
                        response_data += read_file(id)
                elif parsed_data['command'] == 'add_file':
                    file_path = parsed_data['path']
                    # process file and add to filestore
                    file_hash = process_file(file_path)
                    # TODO XXX for now this code assumes the default global identity
                    # publish to DHT
                    message = {
                        'hash': file_hash,
                        'pubbits': identity.get_public_bits().decode('utf-8'),
                        'addrs': collect_addresses(None),
                        'time': time.time()
                    }
                    signature = private_key.sign(json.dumps(message, sort_keys=True).encode('utf-8'),
                                                 ec.ECDSA(hashes.SHA256()))
                    signed_message = {'message': message, 'sig': base64.b64encode(signature).decode('utf-8')}
                    log("Processed file %s\n" % signed_message)
                    file_hash_b64 = base64.b64encode(bytes.fromhex(file_hash)).decode('utf-8')
                    kademlia_do_store(file_hash_b64, signed_message)
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
                elif parsed_data['command'] == 'DEBUG__dht_add':
                    _kademlia_add_node(parsed_data)
                    response_data += 'SUCCESS'

        self.send_response(200)
        self.end_headers()

        if response_data:
            self.wfile.write(response_data.encode('utf-8'))

def shutdown_json_rpc():
    if httpd_instance:
        log("Shutting down JSON-RPC server")
        httpd_instance.shutdown()

def start_json_rpc(port):
    global httpd_instance

    with socketserver.TCPServer(("", port), BiblionRPCRequestHandler) as httpd:
        httpd_instance = httpd
        log("JSON-RPC serving at port: %s" % port)
        try:
            httpd.serve_forever()
        except:
            log("Exception occurred in HTTP server")
        log("Cleaning up JSON-RPC TCPServer")

    httpd_instance = None
