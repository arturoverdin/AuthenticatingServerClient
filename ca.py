import socket
import argparse
import signal
import sys

from datetime import datetime, timedelta

from threading import Thread

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID


threads = []
def signal_handler(signal, frame):
    if sock:
        sock.close()
    print("terminating server...", flush=True)
    sys.exit()


def generate_sign():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open("ca_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

    print("ca public key: %s" % key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo

    ).decode('utf-8'))

    print("ca private key: %s" % key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
    ).decode('utf-8'))

    print("ca certificate: COUNTRY_NAME = US,\n"
          "                PROVINCE NAME = California,\n"
          "                LOCALITY_NAME = Los Angeles,\n"
          "                ORGANIZATION_NAME = USC,\n"
          "                COMMON_NAME = Trusted CA")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Los Angeles"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"USC"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Trusted CA"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.utcnow() + timedelta(days=30)

    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
        # Sign our certificate with our private key
    ).sign(key, hashes.SHA256())

    # Write our certificate out to disk.
    with open("ca_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key


class ProcessRequest(Thread):
    def __init__(self, conn, client_address, private_key):
        Thread.__init__(self)
        self.conn = conn
        self.key = private_key
        self.address = client_address

    def run(self):

        data = self.conn.recv(2048)

        if data:

            csr = x509.load_pem_x509_csr(data)

            client_public_key = csr.public_key()

            CN = csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
            SN = csr.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value
            LN = csr.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value
            ON = csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
            COM = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

            print("received certificate request from %s host %s port %s" % (COM, self.address[0], self.address[1]))
            subject = (x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, CN),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, SN),
                x509.NameAttribute(NameOID.LOCALITY_NAME, LN),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, ON),
                x509.NameAttribute(NameOID.COMMON_NAME, COM),
            ]))
            issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Los Angeles"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"USC"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"Trusted CA"),
            ])
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                client_public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=5)
            ).sign(self.key, hashes.SHA256())

            with open(str(COM) + "_certificate.pem", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

        else:
            pass


if __name__ == "__main__":

    # takes care of the SIGINT
    signal.signal(signal.SIGINT, signal_handler)

    # takes care of all the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", required=True
                        , help="Port number of server."
                        , type=int)

    args = parser.parse_args()

    CA_IP = "127.0.0.1"
    CA_PORT = args.p

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((CA_IP, CA_PORT))
    print("ca started on %s at port %s" % (CA_IP, CA_PORT))

    # generate private and self sign
    private_key = generate_sign()

    # process first CSR
    sock.listen(1)
    client_connection, client_address = sock.accept()
    tcpThread1 = ProcessRequest(client_connection, client_address, private_key)
    tcpThread1.start()

    # process second CRS
    sock.listen(1)
    server_connection, server_address = sock.accept()
    tcpThread2 = ProcessRequest(server_connection, server_address, private_key)
    tcpThread2.start()

    tcpThread1.join()
    tcpThread2.join()

    with open("Client_certificate.pem", "rb") as f1:
        client_cert = x509.load_pem_x509_certificate(f1.read()).public_bytes(serialization.Encoding.PEM)
    with open("Server_certificate.pem", "rb") as f2:
        serv_cert = x509.load_pem_x509_certificate(f2.read()).public_bytes(serialization.Encoding.PEM)

    client_connection.send(serv_cert)

    client_connection.send(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    server_connection.send(client_cert)
    server_connection.send(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    server_connection.close()
    client_connection.close()
