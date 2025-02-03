import os
import zlib
from base64 import b64encode
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as paddingg


#Funkcija za generisanje para privatnog i javnog kljuca
def generate_rsa_keys(key_size_bits):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size_bits,
        backend=default_backend())
    public_key = private_key.public_key()

    return (private_key, public_key)


# Funkcija za serijalizaciju privatnog ključa
def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


# Funkcija za serijalizaciju javnog ključa
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


# Funkcija za deserijalizaciju privatnog ključa
def deserialize_private_key(private_key_bytes, password=None):
    if password is not None:
        password = password.encode()
    return serialization.load_pem_private_key(
        private_key_bytes,
        password=password,
        backend=default_backend()
    )


# Funkcija za deserijalizaciju javnog ključa
def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )


class PrivateKeyRing:

    def __init__(self, name: str, username: str, private_key: RSAPrivateKey):
        self.name = name
        self.email = username
        self.private_key = serialize_private_key(private_key)
        self.public_key = serialize_public_key(private_key.public_key())
        self.keyID = private_key.public_key().public_numbers().n & ((1 << 64) - 1)
        self.timestamp = datetime.now()


class PublicKeyRing:

    def __init__(self, name: str, username: str, public_key: RSAPublicKey):
        self.timestamp = datetime.now()
        self.name = name
        self.email = username
        self.public_key = serialize_public_key(public_key)
        self.keyID = public_key.public_numbers().n & ((1 << 64) - 1)


def sendMessage(message: str, privateKey: PrivateKeyRing, publicKey: PublicKeyRing, algorithm: str, isCompress: bool,
                isBase64: bool, isSign: bool, isEncript: bool, filepath: str):
    heders = 'Encryption-Key-Id: ' + (str(publicKey.keyID) if isEncript else "None") + \
             '\nEncryption-Algorithm: ' + (algorithm if isEncript else "None") + \
             '\nSigning-Key-Id: ' + (str(privateKey.keyID) if isSign else "None") + \
             '\nCompressed: ' + ("True" if isCompress else "False") + \
             '\nRadix-64: ' + ("True" if isBase64 else "False")
    timestamp = "\nTimestamp: " + datetime.now().strftime('%d.%m.%Y %H:%M:%S')
    message += timestamp
    message_encode = message.encode("utf-8")
    signature = ""
    if isSign:
        deserialized_private_key = serialization.load_pem_private_key(privateKey.private_key, password=None,
                                                                      backend=default_backend())
        digest = hashes.Hash(hashes.SHA1())
        digest.update(message_encode)
        hash_bytes = digest.finalize()
        signature += "\nSignature:\n" + deserialized_private_key.sign(hash_bytes, padding.PKCS1v15(),
                                                                        hashes.SHA1()).hex()

    if isCompress:
        message_encode = zlib.compress(message_encode)

    if isEncript:
        deserialized_public_key = serialization.load_pem_public_key(publicKey.public_key, backend=default_backend())
        iv = os.urandom(16)
        simetricKey = os.urandom(16)
        cipher = Cipher(algorithms.AES(simetricKey), modes.CBC(iv)) if algorithm == "AES" else Cipher(
                algorithms.TripleDES(simetricKey), modes.CBC(iv[:8]))
        padder = paddingg.PKCS7(algorithms.AES.block_size).padder() if algorithm == "AES" else paddingg.PKCS7(
                algorithms.TripleDES.block_size).padder()
        padded_message = padder.update(message_encode) + padder.finalize()
        encryptor = cipher.encryptor()

        encripted_message = encryptor.update(padded_message) + encryptor.finalize()
        encripted_message = encripted_message.hex()
        encripted_cipher = deserialized_public_key.encrypt(simetricKey, padding.PKCS1v15()).hex()

        message_encode = (iv.hex() if algorithm == "AES" else iv[:8].hex()) + encripted_cipher + encripted_message
        message_encode = message_encode.encode("utf-8")


    s = "\nMessage:\n"
    with open(filepath, "wb") as file:
        file.write(heders.encode("utf-8") + signature.encode("utf-8") + s.encode("utf-8") + message_encode)
    print("Message sent")

def receiveMessage(privateKeys: list[PrivateKeyRing], publicKeys: list[PublicKeyRing], filepath: str):
    headers = {}
    signature = None
    message = None
    with open(filepath, 'rb') as file:
        for i in range(5): #ucitavanje 5 linija zaglavlja
            line = file.readline().strip()
            header = line.split(b': ')
            key, value = header
            headers[key.decode('utf-8')] = value.decode('utf-8')
        line1 = file.readline().strip()
        line2 = file.readline().strip()
        if line1.startswith(b'Sign'):
            signature = line2
            line1 = file.readline().strip()
            line2 = file.readline().strip()
        if line1.startswith(b'Mess:'):
            message = line2
    prKey = headers["Signing-Key-Id"]
    puKey = headers["Encryption-Key-Id"]
    private = None
    public = None
    for pr in privateKeys:
        if (str(pr.keyID) == prKey):
            private = pr

    for pu in publicKeys:
        if(str(pu.keyID) == puKey):
            public = pu


    return (headers,private,public)