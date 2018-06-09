import os
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.interfaces import PEMSerializationBackend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

def get_keys(node_dir=None):
    key_dir = "data/keys"
    if node_dir:
        key_dir = node_dir + '/' + key_dir

    # checks if keys exist for this node, and if not, creates them
    if not os.path.exists("%s/key_dirpub.key" % key_dir):
        print("Missing public key. Generating new keypair.")

        # WARNING: The chosen curve here is considered unsafe by DJB
        # However, it's the same as the curve used by bitcoin
        private_key = ec.generate_private_key(
            ec.SECP256K1(),
            default_backend()
        )

        public_key = private_key.public_key()

        serialized_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        fpriv = open("%s/priv.key" % key_dir, 'wb')
        fpriv.write(serialized_private)
        fpriv.close()

        fpub = open("%s/pub.key" % key_dir, 'wb')
        fpub.write(serialized_public)
        fpub.close()
    else:
        private_key_data = open("%s/priv.key" % key_dir, 'rb').read()
        private_key = serialization.load_pem_private_key(private_key_data,
                                                         None,
                                                         default_backend())

        public_key_data = open("%s/pub.key" % key_dir, 'rb').read()
        public_key = serialization.load_pem_public_key(public_key_data,
                                                       default_backend())
    return public_key, private_key
