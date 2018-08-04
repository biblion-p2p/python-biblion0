# Biblion (PROTOTYPE)

Biblion is a platform for building P2P file sharing communities.

This is a prototype implementation of the Biblion stack. Assume many things are broken, partly
implemented, or untested.

It will support the following network transports:
- TCP (with TLSv1.2, SPDY-like multiplexing)
- UDP

It will support the following services

- Biblion - core biblion meta-protocol (in progress)
- Kademlia (almost done)
- BitTorrent (not started)
- SimpleDownload - a simple ftp-like download protocol (done)
- MetadataSet - track what files are available in a library context (in progress)
- UserSet - track what users are allowed in a library context (in progress)
- NameSet - track a set of (key, value) pairs in a library context, intended for dynamic name resolution (not started)
- Bank - Manage a ledger of peer balances within a library (not started)
- Gossip - send updates throughout a peer network (in progress)
- Blockchain - publically verifable ledger (not started)
- ScryptPoW - an scrypt-based Proof-of-work algorithm (not started)
