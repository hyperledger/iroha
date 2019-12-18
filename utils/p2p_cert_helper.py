#!/usr/bin/env python3

import argparse
import asn1
import datetime
import os
import sys
import typing

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as get_default_crypto_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes

CRYPTO_ENCODING = crypto_serialization.Encoding.PEM
CRYPTO_FORMAT = crypto_serialization.PrivateFormat.PKCS8
CRYPTO_BACKEND = get_default_crypto_backend()
CRYPTO_SIGNATURE_HASH = hashes.SHA256()  # this is just a descriptor

CMD_GEN_REQ = 'gen_req'
CMD_GEN_CERT = 'gen_self_signed_cert'
CMD_SIGN_REQ = 'sign_req'
CMD_EXTRACT_KEYS = 'extract_keys'

OVERRIDEN_SUBJECT_FIELDS = {
    'country': NameOID.COUNTRY_NAME,
    'state': NameOID.STATE_OR_PROVINCE_NAME,
    'locality': NameOID.LOCALITY_NAME,
    'organization': NameOID.ORGANIZATION_NAME,
    'organization-unit': NameOID.ORGANIZATIONAL_UNIT_NAME,
    'common-name': NameOID.COMMON_NAME,
}

OID_ED25519_PUBKEY = x509.ObjectIdentifier('1.3.101.112')


def get_iroha_pubkey(args: argparse.Namespace) -> bytes:
    if args.iroha_pubkey is not None:
        return args.pubkey.encode()
    elif args.iroha_pubkey_path is not None:
        assert (os.path.isfile(args.iroha_pubkey_path))
        with open(args.iroha_pubkey_path, 'rb') as inp:
            return inp.read().strip()
    raise Exception('No iroha public key specified!')


def generate_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537,
                                    key_size=2048,
                                    backend=CRYPTO_BACKEND)


def get_tls_key(args: argparse.Namespace) -> rsa.RSAPrivateKey:
    if args.tls_key_path is not None:
        try:
            with open(args.tls_key_path, 'rb') as inp:
                return crypto_serialization.load_pem_private_key(
                    inp.read(), password=None, backend=CRYPTO_BACKEND)
        except Exception as e:
            raise Exception('Could not load TLS private key.') from e
    elif args.create_and_store_tls_key is not None:
        key = generate_private_key()
        with open(args.create_and_store_tls_key, 'wb') as out:
            out.write(
                key.private_bytes(CRYPTO_ENCODING, CRYPTO_FORMAT,
                                  crypto_serialization.NoEncryption()))
        return key
    raise Exception(
        'No TLS key specified! '
        'Please specify either a path to existing private TLS key, '
        'or a path to store a newly created one.')


def get_csr(args: argparse.Namespace) -> x509.CertificateSigningRequest:
    if args.req is not None:
        try:
            with open(args.req, 'rb') as inp:
                return x509.load_pem_x509_csr(inp.read(), CRYPTO_BACKEND)
        except Exception as e:
            raise Exception('Could not load CSR.') from e
    raise Exception('No CSR path specified!')


def get_cert(args: argparse.Namespace) -> x509.Certificate:
    if args.cert is not None:
        try:
            with open(args.cert, 'rb') as inp:
                return x509.load_pem_x509_certificate(inp.read(),
                                                      CRYPTO_BACKEND)
        except Exception as e:
            raise Exception('Could not load certificate.') from e
    raise Exception('No certificate path specified!')


def make_ed15519_pubkey_san_extension(pubkey: bytes) -> x509.ExtensionType:
    enc = asn1.Encoder()
    enc.start()
    enc.write(pubkey, asn1.Numbers.OctetString, asn1.Types.Primitive)
    der_key = enc.output()
    return x509.SubjectAlternativeName([
        x509.DNSName('iroha'),
        x509.OtherName(OID_ED25519_PUBKEY, value=der_key),
    ])


def fill_subject_from_args(args: argparse.Namespace) -> x509.Name:
    # fill default values
    key_prefix = get_iroha_pubkey(args)[:8].decode()
    name_attrs = {
        NameOID.COUNTRY_NAME: 'JP',
        NameOID.STATE_OR_PROVINCE_NAME: 'Japan',
        NameOID.LOCALITY_NAME: 'Aizu',
        NameOID.ORGANIZATION_NAME: 'One World',
        NameOID.ORGANIZATIONAL_UNIT_NAME: 'example',
        NameOID.COMMON_NAME: 'iroha peer {}'.format(key_prefix),
    }

    # override from with args
    for arg, oid in OVERRIDEN_SUBJECT_FIELDS.items():
        override = args.__dict__.get(arg.replace('-', '_'))
        if override is not None:
            name_attrs[oid] = override

    return x509.Name(
        x509.NameAttribute(oid, val) for (oid, val) in name_attrs.items())


def make_req(args: argparse.Namespace) -> bytes:
    req_builder = x509.CertificateSigningRequestBuilder()
    req_builder = req_builder.subject_name(fill_subject_from_args(args))
    req_builder = req_builder.add_extension(make_ed15519_pubkey_san_extension(
        get_iroha_pubkey(args)),
                                            critical=True)

    tls_key = get_tls_key(args)
    req = req_builder.sign(tls_key, CRYPTO_SIGNATURE_HASH, CRYPTO_BACKEND)
    return req.public_bytes(CRYPTO_ENCODING)


def make_cert(args: argparse.Namespace) -> bytes:
    cert_builder = x509.CertificateBuilder()
    subject_and_issuer = fill_subject_from_args(args)
    cert_builder = cert_builder.subject_name(subject_and_issuer)
    cert_builder = cert_builder.issuer_name(subject_and_issuer)
    cert_builder = cert_builder.add_extension(
        make_ed15519_pubkey_san_extension(get_iroha_pubkey(args)),
        critical=True)
    cert_builder = cert_builder.not_valid_before(datetime.datetime.today() -
                                                 datetime.timedelta(days=1))
    cert_builder = cert_builder.not_valid_after(datetime.datetime.today() +
                                                datetime.timedelta(days=365))
    cert_builder = cert_builder.serial_number(x509.random_serial_number())

    tls_key = get_tls_key(args)
    cert_builder = cert_builder.public_key(tls_key.public_key())
    cert = cert_builder.sign(tls_key, CRYPTO_SIGNATURE_HASH, CRYPTO_BACKEND)

    return cert.public_bytes(CRYPTO_ENCODING)


def sign_req(args: argparse.Namespace) -> bytes:
    req = get_csr(args)
    ca_cert = get_cert(args)
    ca_key = get_tls_key(args)
    if not ca_cert.public_key().public_numbers() \
            == ca_key.public_key().public_numbers():
        raise Exception('Provided CA key does not match the CA certificate.')

    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(fill_subject_from_args(args))
    cert_builder = cert_builder.issuer_name(ca_cert.subject)
    for extension in req.extensions:
        cert_builder = cert_builder.add_extension(extension.value,
                                                  extension.critical)
    cert_builder = cert_builder.not_valid_before(datetime.datetime.today() -
                                                 datetime.timedelta(days=1))
    cert_builder = cert_builder.not_valid_after(datetime.datetime.today() +
                                                datetime.timedelta(days=365))
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.public_key(req.public_key())

    cert = cert_builder.sign(ca_key, CRYPTO_SIGNATURE_HASH, CRYPTO_BACKEND)

    return cert.public_bytes(CRYPTO_ENCODING)


def get_keys(args: argparse.Namespace) -> typing.Generator[bytes, None, None]:
    def try_load(loader):
        try:
            return loader(args)
        except Exception:
            return None

    something = try_load(get_cert) or try_load(get_csr)
    if not something:
        raise Exception(
            'Please specify either a certificate or a certificate request.')

    ASN1_OCTET_STRING_TAG = asn1.Tag(4, 0, 0)

    asn1_key_iter = (
        san.value for san_extension in something.extensions
        if san_extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        for san in san_extension.value if isinstance(san, x509.OtherName)
        and san.type_id == OID_ED25519_PUBKEY)

    for asn1_key in asn1_key_iter:
        decoder = asn1.Decoder()
        decoder.start(asn1_key)
        tag, value = decoder.read()
        if tag != ASN1_OCTET_STRING_TAG:
            continue
        yield value


def get_keys_joined(args: argparse.Namespace,
                    delimiter: bytes = os.linesep.encode()) -> bytes:
    return delimiter.join(get_keys(args))


COMMANDS = {
    CMD_GEN_REQ: make_req,
    CMD_GEN_CERT: make_cert,
    CMD_SIGN_REQ: sign_req,
    CMD_EXTRACT_KEYS: get_keys_joined
}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--iroha-pubkey',
                        help='Public key of iroha peer as a hex string.',
                        required=False)
    parser.add_argument(
        '--iroha-pubkey-path',
        help=
        'Path to file containing public key of iroha peer as a hex string.',
        required=False)
    parser.add_argument('--tls-key-path',
                        help='Path to TLS private key in PEM format.',
                        required=False)
    parser.add_argument(
        '--create-and-store-tls-key',
        help='Path to store a newly created TLS private key in PEM format.',
        required=False)
    parser.add_argument('--req',
                        help='Path to certificate request in PEM format.',
                        required=False)
    parser.add_argument('--cert',
                        help='Path to certificate in PEM format.',
                        required=False)
    parser.add_argument(
        '-O',
        '--output-file',
        help=
        'Output file path. If not provided, contents will be written to stdout.',
        required=False)
    for field in OVERRIDEN_SUBJECT_FIELDS:
        parser.add_argument('--{}'.format(field),
                            help='certificate subject {}'.format(
                                OVERRIDEN_SUBJECT_FIELDS[field]),
                            required=False)
    parser.add_argument('command', choices=COMMANDS, help='Action.')
    args = parser.parse_args()

    output_dest = args.output_file and open(args.output_file,
                                            'wb') or sys.stdout.buffer

    output_dest.write(COMMANDS[args.command](args).strip())
    output_dest.write(os.linesep.encode())
