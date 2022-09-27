#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from microstack_init.shell import check

from datetime import datetime
from dateutil.relativedelta import relativedelta
from pathlib import Path
import ipaddress
import socket

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

from microstack_init import shell


def create_or_get_private_key(key_path: Path) -> rsa.RSAPrivateKey:
    """Generate a local private key file.

    :param key_path: path of the key
    :type key_path: Path
    :return: private key
    :rtype: rs.RSAPrivateKey
    """
    # If the key path exists, then attempt to load it in order to make sure
    # it is a valid private key.
    if key_path.exists():
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(
                f.read(), None, default_backend()
            )
            if not isinstance(key, rsa.RSAPrivateKey):
                raise TypeError(
                    "Private key already exists but is not an " "RSA key"
                )
            return key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    serialized_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(serialized_key)
    check("chmod", "600", str(key_path))
    return key


def generate_self_signed(
    cert_path, key_path, ip=None, fingerprint_config=None
):
    """Generate a self-signed certificate with associated keys.

    The certificate will have a fake CNAME and subjAltName since
    the expectation is that this certificate will only be used by
    clients that know its fingerprint and will not use a validation
    via a CA certificate and hostname. This approach is similar to
    Certificate Pinning, however, here a certificate is not embedded
    into the application but is generated on microstack_initialization at one
    node and its fingerprint is copied in a token to another node
    via a secure channel.
    https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning
    """
    # Do not generate a new certificate and key if there is already an existing
    # pair. TODO: improve this check and allow renewal.
    if cert_path.exists():
        return

    key = create_or_get_private_key(key_path=key_path)
    cn = socket.getfqdn()
    common_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    if ip:
        san = x509.SubjectAlternativeName(
            [x509.DNSName(cn), x509.IPAddress(ipaddress.ip_address(ip))]
        )
    else:
        san = x509.SubjectAlternativeName([x509.DNSName(cn)])

    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)

    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(common_name)
        .issuer_name(common_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + relativedelta(years=10))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )

    cert_fprint = cert.fingerprint(hashes.SHA256()).hex()
    if fingerprint_config:
        shell.config_set(**{fingerprint_config: cert_fprint})

    serialized_cert = cert.public_bytes(encoding=serialization.Encoding.PEM)
    cert_path.write_bytes(serialized_cert)
    check("chmod", "644", str(cert_path))


def create_csr(
    key_path: Path, ip: str = None
) -> x509.CertificateSigningRequest:
    """Creates a Certificate Signing Request (CSR) for the local node.

    A CSR is created for the local node. The resulting CSR can be provided to
    generate a Certificate in a PKI infrastructure. The CSR will be generated
    using the local nodes hostname as the CN and SAN in the request. The CSR
    generated will not request certificate authority.

    :param key_path: the path to the local private key file
    :type key_path: Path
    :param ip: the ip address of the local node
    :type str: the ip address of the local node
    :returns: x509.CertificateSigningRequest object for the local node
    :rtype: x509.CertificateSigningRequest
    """
    with open(key_path, "rb+") as f:
        key = serialization.load_pem_private_key(
            f.read(), None, default_backend()
        )

    hostname = socket.getfqdn()
    cn = x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    if ip:
        san = x509.SubjectAlternativeName(
            [x509.DNSName(cn), x509.IPAddress(ipaddress.ip_address(ip))]
        )
    else:
        san = x509.SubjectAlternativeName([x509.DNSName(hostname)])
    not_ca = x509.BasicConstraints(ca=False, path_length=None)

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([cn]))
    builder = builder.add_extension(san, critical=False)
    builder = builder.add_extension(not_ca, critical=True)

    request = builder.sign(key, hashes.SHA256(), backend=default_backend())
    return request.public_bytes(serialization.Encoding.PEM)


def generate_cert_from_csr(ca_path, key_path, client_csr):
    """Generates a certificate from a Certificate Signing Request (CSR).

    :param ca_path: the path to the ca cert
    :type ca_path: str or Path
    :param key_path: the path to the ca cert key file
    :type key_path: str or Path
    :param client_csr: the certificate signing request from a client
    :return: PEM encoded certificate
    :rtype: bytes
    """
    with open(ca_path, "rb") as f:
        cacert = x509.load_pem_x509_certificate(f.read(), default_backend())

    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), None, default_backend()
        )

    csr = x509.load_pem_x509_csr(client_csr, default_backend())

    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(cacert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(
            # Set it to expire 2 days before our cacert does
            cacert.not_valid_after
            - relativedelta(days=2)
        )
    )

    # Add requested extensions
    for extension in csr.extensions:
        builder.add_extension(extension.value, extension.critical)

    cert = builder.sign(key, hashes.SHA256(), default_backend())
    return cert.public_bytes(encoding=serialization.Encoding.PEM)
