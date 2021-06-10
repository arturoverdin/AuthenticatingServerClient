import os
import socket
import argparse
import signal
import sys
import time
from hashlib import sha256

from threading import Thread

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher

from cryptography.x509.oid import NameOID


def signal_handler(signal, frame):
    print("terminating server...", flush=True)
    sys.exit()


def generate_keys_csr(ca_socket):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open("client_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print("client public key: %s" % key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo

    ).decode('utf-8'))

    print("client private key: %s" % key.private_bytes(
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
        x509.NameAttribute(NameOID.COMMON_NAME, u"Client"),
    ])).sign(key, hashes.SHA256())
    # Write our CSR out to disk.
    with open("client_csr.pem", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print("sending certificate request to CA: %s port %s" % (CA_IP, CA_PORT))
    ca_socket.send(csr.public_bytes(serialization.Encoding.PEM))

    server_cert = ca_socket.recv(2048)
    ca_public = ca_socket.recv(2048)
    server_cert = x509.load_pem_x509_certificate(server_cert)

    COM = server_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    CN = server_cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
    LN = server_cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
    ON = server_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    SN = server_cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value

    print("received server certificate: COUNTRY_NAME = %s,\n"
          "                PROVINCE NAME = %s,\n"
          "                LOCALITY_NAME = %s,\n"
          "                ORGANIZATION_NAME = %s,\n"
          "                COMMON_NAME = %s" % (CN, SN, LN, ON, COM))

    return key


if __name__ == "__main__":
    # takes care of the SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    # takes care of all the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", required=True
                        , help="Port number of server"
                        , type=int)

    parser.add_argument("-s", required=True
                        , help="IP address of the server.")

    parser.add_argument("-ss", required=True
                        , help="IP for the ca server.")

    parser.add_argument("-pp", required=True
                        , help="Port number used for ca server."
                        , type=int)

    parser.add_argument("-m", required=True
                        , help="Message to be sent to server.")

    args = parser.parse_args()

    SERVER_IP = "127.0.0.1"
    SERVER_PORT = args.p
    CA_IP = args.ss
    CA_PORT = args.pp
    MESSAGE = str(args.m)

    ca_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ca_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ca_sock.connect((CA_IP, CA_PORT))
    print("client started on %s at port %s" % (SERVER_IP, ca_sock.getsockname()[1]))

    PRIVATE_KEY = generate_keys_csr(ca_sock)

    backend = default_backend()
    secret_key = os.urandom(16)
    iv = os.urandom(16)

    print("generated AES key: " + str(secret_key))

    hashed_message = sha256(MESSAGE.encode('utf-8')).hexdigest()

    signature = PRIVATE_KEY.sign(hashed_message.encode('utf-8'),
                                 padding.PSS(
                                     mgf=padding.MGF1(hashes.SHA256()),
                                     salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA256())

    print("message signature: " + str(signature))

    encrypted_key = PRIVATE_KEY.public_key().encrypt(
        secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(secret_key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    encryptor_two = cipher.encryptor()

    encrypted_mess = encryptor.update(MESSAGE.encode('utf-8')) + encryptor.finalize()
    print("encrypted message: " + str(encrypted_mess))

    encrypted_sig = encryptor_two.update(signature) + encryptor_two.finalize()

    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((SERVER_IP, SERVER_PORT))
            break
        except socket.error:
            time.sleep(1)

    sock.send(signature)
    sock.send(encrypted_key)
    sock.send(encrypted_sig)
    sock.send(secret_key)
    sock.send(iv)
    print("sending encrypted message to server")
    sock.send(encrypted_mess)

    enc_server_mess = sock.recv(2048)

    decryptor = cipher.decryptor()
    dec_server_mess = decryptor.update(enc_server_mess) + decryptor.finalize()
    dec_server_mess = dec_server_mess.decode('utf-8')
    print("received server response: " + str(dec_server_mess))

