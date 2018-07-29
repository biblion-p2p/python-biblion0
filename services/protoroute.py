"""
In the nearish future, we will need to refer to protocol ids by number instead
of by string name. For supporting QUIC, we'll need to encode the protocol id
as part of the stream id. The only safe way to do this is to assign a number
to each protocol. Protocol numbers can be established by having each peer say
Hello to each other.

But there is a problem. We want nodes to be able to make requests quickly
WITHOUT waiting for another round trip for protocol negotiation. This is where
ProtoRoute comes in. This will be a default service assumed to exist in any
node we connect to, much like the Biblion service. The ProtoRoute service wraps
any other service, and allows you to identify the service by a string instead.
This allows nodes to immediately start sending messages to each other at an
arbitrary service, with the cost of additional overhead for each stream. This
overhead is worth it when low latency is the most important factor in an exchange.
So during a Kademlia lookup or bootstrap, Kademlia will use ProtoRoute to send
its messages without waiting for a protocol negotiation. We only have to wait for
for the crypto handshake. Using 0RTT, this means we can use ProtoRoute to send
an encrypted message in a single hop!

XXX: This is unnecessary for now, because I encode the service id as a string anyway.

ProtoRoute should have a low level reserved servce id, such as `2`.
"""



class ProtoRoute(object):
    pass
