from hashlib import sha256

from cryptography.fernet import Fernet
import socket
import argparse
import signal
import sys
from threading import Thread

from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.x509.oid import NameOID


def signal_handler(signal, frame):
    print("terminating server...", flush=True)
    sys.exit()


class ProcessRequest(Thread):
    def __init__(self, sock, address, message, public_client):
        Thread.__init__(self)
        self.tcpsocket = sock
        self.address = address
        self.message = message
        self.client_pub = public_client

    def run(self):

        self.tcpsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcpsocket.bind(self.address)
        self.tcpsocket.listen(1)

        server_connection, client_address = self.tcpsocket.accept()
        signature = server_connection.recv(256)
        encrypted_key = server_connection.recv(256)
        encrypted_sig = server_connection.recv(256)
        secret_key = server_connection.recv(16)
        iv = server_connection.recv(16)
        encrypted_mess = server_connection.recv(256)

        cipher = Cipher(algorithms.AES(secret_key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        decrypt_message = decryptor.update(encrypted_mess) + decryptor.finalize()

        print("received message from client: " + decrypt_message.decode('utf-8'))

        hashed_mess = sha256(decrypt_message).hexdigest().encode('utf-8')

        self.client_pub.verify(
            signature,
            hashed_mess,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("integrity check: calculated = " + str(hashed_mess.decode('utf-8')) + " and passed.")

        encrpytor = cipher.encryptor()
        encrypt_message = encrpytor.update(str(self.message).encode('utf-8')) + encrpytor.finalize()

        print("sending message to client: " + str(encrypt_message))

        server_connection.send(encrypt_message)
        server_connection.close()


def generate_keys_csr(ca_socket):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open("server_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print("server public key: %s" % key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo

    ).decode('utf-8'))

    print("server private key: %s" % key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ).decode('utf-8'))

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Los Angeles"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"USC"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Server"),
    ])).sign(key, hashes.SHA256())
    # Write our CSR out to disk.
    with open("server_csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print("sending certificate request to CA: %s port %s" % (CA_IP, CA_PORT))
    ca_socket.send(csr.public_bytes(serialization.Encoding.PEM))

    client_cert = ca_socket.recv(2048)
    ca_public = ca_socket.recv(2048)
    client_cert = x509.load_pem_x509_certificate(client_cert)
    client_public = client_cert.public_key()

    COM = client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    CN = client_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    LN = client_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
    ON = client_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    SN = client_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value

    print("received client certificate: COUNTRY_NAME = %s,\n"
          "                PROVINCE NAME = %s,\n"
          "                LOCALITY_NAME = %s,\n"
          "                ORGANIZATION_NAME = %s,\n"
          "                COMMON_NAME = %s" % (CN, SN, LN, ON, COM))

    return key, client_public

if __name__ == "__main__":
    # takes care of the SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    # takes care of all the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", required=True
                        , help="Add port number to run server on."
                        , type=int)

    parser.add_argument("-ss", required=True
                        , help="IP address of the ca server.")

    parser.add_argument("-pp", required=True
                        , help="Port number of the ca server."
                        , type=int)

    parser.add_argument("-m", required=True
                        , help="Message server responds with.")

    args = parser.parse_args()

    SERVER_IP = "127.0.0.1"
    SERVER_PORT = args.p
    CA_IP = args.ss
    CA_PORT = args.pp
    MESSAGE = args.m

    print("server started on 127.0.0.1 at port %s" % SERVER_PORT, flush=True)

    ca_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ca_socket.connect((CA_IP, CA_PORT))
    PRIVATE_KEY, PUBLIC_CLIENT = generate_keys_csr(ca_socket)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (SERVER_IP, SERVER_PORT)
    tcpThread = ProcessRequest(sock, server_address, MESSAGE, PUBLIC_CLIENT)

    tcpThread.start()
