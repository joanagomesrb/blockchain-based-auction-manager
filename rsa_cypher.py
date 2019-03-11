
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import base64
import logging

class RSACypher:
    def __init__(self, public_key=None, private_key=None):
        self.public_key = public_key
        self.private_key = private_key

    def generate_key_pair(self, identity):
        #new_key = RSA.generate(2048, 65537)
        # self.public_key = new_key.publickey().exportKey("PEM")
        # self.private_key = new_key.exportKey("PEM")

        # generate private_key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

       # serialize private_key
        pem_private_key = self.private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=serialization.NoEncryption())

        # serialize public_key
        self.public_key = self.private_key.public_key()
        pem_public_key = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                           format=serialization.PublicFormat.SubjectPublicKeyInfo)

        self.write_on_file(pem_public_key, pem_private_key, identity)

        return self.public_key, self.private_key

    def write_on_file(self, public_key, private_key, identity):
        if identity == "Manager":
            f = open("manager_public_key.pem", "wb")
            f.write(public_key)
            f.close
            f = open("manager_private_key.pem", "wb")
            f.write(private_key)
            f.close
        elif identity == "Repository":
            f = open("repository_public_key.pem", "wb")
            f.write(public_key)
            f.close
            f = open("repository_private_key.pem", "wb")
            f.write(private_key)
            f.close

   
    def encrypt(self, message, pub_key):
        cipher = PKCS1_OAEP.new(pub_key)
        return base64.b64encode(cipher.encrypt(message))

    def decrypt(self, message):
        priv_key = RSA.importKey(self.private_key)
        return priv_key.decrypt(base64.b64decode(message))

    def load_public_key(self, identity):
        file_to_open = ("{}_public_key.pem").format(identity)
        logging.warning(file_to_open)
        with open(file_to_open, "rb") as key_file:
            public_key = serialization.load_pem_public_key(     key_file.read(),
                                                                backend=default_backend())
        return public_key