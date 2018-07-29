# A service must be able to handle incoming requests that are directed towards that service
# A service must be able to handle incoming calls from the RPC. This is a form of incoming request anyway.
# A service may subscribe to incoming peer event, and possibly talk to that peer
# A service may have a bootstrap routine, that gets called when Biblion is starting
# During bootstrap, the service can set up scheduled tasks to be run occasionally (ie. STORE refresh)

import gevent

from log import log

class ServiceManager(object):
    def __init__(self, identity):
        self.identity = identity
        self._services = {}

    def register_service(self, service_id, service):
        self._services[service_id] = service

    def route_stream(self, stream):
        if stream.service_id in self._services:
            self._services[stream.service_id].handle_message(stream)
        else:
            log("Discarding message for unknown service")

    def start_all(self):
        for service in self._services.values():
            gevent.spawn(service.start)

    def get_service(self, service_id):
        if service_id not in self._services:
            # XXX make a useful exception
            raise
        return self._services[service_id]
