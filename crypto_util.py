import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

def pub_to_nodeid(pubkey):
    pub_bits = pubkey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_bits_to_peer_id(pub_bits)

def public_bits_to_peer_id(public_bits):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(public_bits)
    return base64.b64encode(digest.finalize()).decode("utf-8")
