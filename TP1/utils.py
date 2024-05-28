import datetime
import sys
import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509


class HandshakeInfo:
    def __init__(self, params=None, private_key_dl=None, public_key_dl=None, public_key_dl_pem=None,
                 shared_key=None, derived_key=None, peer_pseudonym=None, derived_key_hmac=None) -> None:
        self.params = params
        self.private_key_dl = private_key_dl
        self.public_key_dl = public_key_dl
        self.public_key_dl_pem = public_key_dl_pem
        self.shared_key = shared_key
        self.aes_key = derived_key
        self.hmac_key = derived_key_hmac
        self.peer_pseudonym = peer_pseudonym


def get_p12_data(p12_file_name):
    with open(p12_file_name, "rb") as f:
        p12 = f.read()
    password = None
    (private_key, cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password)
    return private_key, cert, ca_cert


def print_cert(cert):
    print(f"Subject: {cert.subject}")
    print(f"Issuer: {cert.issuer}")
    print(f"Valid from: {cert.not_valid_before_utc}")
    print(f"Valid to: {cert.not_valid_after_utc}")
    print(f"Serial number: {cert.serial_number}")
    print(f"Version: {cert.version}")
    print(f"Extensions: {cert.extensions}")


def read_file_as_bytes(file_path: str) -> bytes:
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    with open(file_path, 'rb') as file:
        byte_list = file.read()
    return byte_list


def write_bytes_to_file(file_path: str, byte_list: bytes):
    with open(file_path, 'wb') as file:
        file.write(byte_list)


def cert_load(f_name):
    with open(f_name, "rb") as f_cert:
        cert = x509.load_pem_x509_certificate(f_cert.read())
    return cert


def cert_valid_time(cert, now=None):

    if now is None:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise x509.verification.VerificationError("Certificate is not valid at this time")


def cert_valid_subject(cert, attrs=None):
    if attrs is None:
        attrs = []
    for attr in attrs:
        if cert.subject.get_attributes_for_oid(attr[0])[0].value != attr[1]:
            raise x509.verification.VerificationError("Certificate subject does not match expected value")


def cert_valid_extensions(cert, policy=None):
    if policy is None:
        policy = []
    for check in policy:
        ext = cert.extensions.get_extension_for_oid(check[0]).value
        if not check[1](ext):
            raise x509.verification.VerificationError("Certificate extensions does not match expected value")


def get_pseudonym_from_certificate(cert) -> str | None:
    try:
        pseudonym_attributes = cert.subject.get_attributes_for_oid(x509.NameOID.PSEUDONYM)
        if pseudonym_attributes:
            return pseudonym_attributes[0].value
        else:
            return None
    except AttributeError:
        return None
    except IndexError:
        return None


def validate_cert(cert, ca_cert, attrs, policy) -> bool:
    try:
        cert.verify_directly_issued_by(ca_cert)
        cert_valid_time(cert)
        cert_valid_subject(cert, attrs)
        cert_valid_extensions(cert, policy)
        return True
    except:
        return False


def get_agreed_kdf(salt: bytes) -> PBKDF2HMAC:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=100000,
    )
