#!/usr/bin/env python3

import argparse
import os
import sys
import typing

from OpenSSL import crypto

CMD_GEN_REQ = 'gen_req'
CMD_GEN_CERT = 'gen_self_signed_cert'
CMD_SIGN_REQ = 'sign_req'
CMD_EXTRACT_KEYS = 'extract_keys'

OVERRIDEN_SUBJECT_FIELDS = {
    'country': 'C',
    'state': 'ST',
    'locality': 'L',
    'organization': 'O',
    'organization-unit': 'OU',
}


def get_iroha_pubkey(args: argparse.Namespace) -> str:
    if args.iroha_pubkey is not None:
        return args.pubkey
    elif args.iroha_pubkey_path is not None:
        assert (os.path.isfile(args.iroha_pubkey_path))
        with open(args.iroha_pubkey_path, 'rt') as inp:
            return inp.read().strip()
    raise Exception('No iroha public key specified!')


def get_tls_key(args: argparse.Namespace) -> crypto.PKey:
    if args.tls_key_path is not None:
        with open(args.tls_key_path, 'rt') as inp:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, inp.read())
    elif args.create_and_store_tls_key is not None:
        key = crypto.PKey()
        key.generate_key(type=crypto.TYPE_RSA, bits=1024)
        with open(args.create_and_store_tls_key, 'wb') as out:
            out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        return key
    raise Exception(
        'No TLS key specified! '
        'Please specify either a path to existing private TLS key, '
        'or a path to store a newly created one.')


def get_csr(args: argparse.Namespace) -> crypto.X509Req:
    if args.req is not None:
        with open(args.req, 'rt') as inp:
            return crypto.load_certificate_request(crypto.FILETYPE_PEM,
                                                   inp.read())
    raise Exception('No CSR path specified!')


def get_cert(args: argparse.Namespace) -> crypto.X509:
    if args.cert is not None:
        with open(args.cert, 'rt') as inp:
            return crypto.load_certificate(crypto.FILETYPE_PEM, inp.read())
    raise Exception('No certificate path specified!')


def make_iroha_san_extension(pubkey: str) -> crypto.X509Extension:
    return crypto.X509Extension(b'subjectAltName',
                                critical=True,
                                value=b'DNS:iroha' + pubkey.encode())


def make_ed15519_pubkey_san_extension(pubkey: str) -> crypto.X509Extension:
    return crypto.X509Extension(b'subjectAltName',
                                critical=True,
                                value=b'otherName:1.3.101.112;INT:0x' +
                                pubkey.encode())


def fill_subject_from_args(subject: crypto.X509Name, args: argparse.Namespace) -> None:
    # fill default values
    subject.C = 'JP'
    subject.ST = 'Japan'
    subject.L = 'Aizu'
    subject.O = 'One World'
    subject.OU = 'example'
    subject.CN = 'iroha'

    # override from with args
    for arg, attr_name in OVERRIDEN_SUBJECT_FIELDS.items():
        override = args.__dict__.get(arg.replace('-', '_'))
        if override is not None:
            setattr(subject, attr, override)


def make_req(args: argparse.Namespace) -> str:
    req = crypto.X509Req()
    fill_subject_from_args(req.get_subject(), args)
    req.add_extensions(
        [make_ed15519_pubkey_san_extension(get_iroha_pubkey(args))])
    tls_key = get_tls_key(args)
    req.set_pubkey(tls_key)
    req.sign(tls_key, 'sha1')
    return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req).decode()


def make_cert(args: argparse.Namespace) -> str:
    cert = crypto.X509()
    fill_subject_from_args(cert.get_subject(), args)
    cert.add_extensions(
        [make_ed15519_pubkey_san_extension(get_iroha_pubkey(args))])
    tls_key = get_tls_key(args)
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(tls_key)
    cert.sign(tls_key, 'sha1')
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()


def sign_req(args: argparse.Namespace) -> str:
    req = get_csr(args)
    ca_cert = get_cert(args)
    tls_key = get_tls_key(args)
    if not ca_cert.get_pubkey().to_cryptography_key().public_numbers() \
            == tls_key.to_cryptography_key().public_key().public_numbers():
        raise Exception('Provided TLS key does not match the CA certificate.')
    cert = crypto.X509()
    cert.set_subject(req.get_subject())
    cert.add_extensions(req.get_extensions())
    cert.set_serial_number(1)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(tls_key, 'sha1')
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()

def get_keys(args: argparse.Namespace) -> typing.Generator[str, None, None]:
    def try_load(loader):
        try:
            return loader(args)
        except Exception:
            return None

    something = try_load(get_cert) or try_load(get_csr)
    if not something:
        raise Exception('Please specify either a certificate or a certificate request.')

    if hasattr(something, 'get_extensions'):
        extensions = something.get_extensions()
    elif all(hasattr(something, a) for a in ('get_extension_count', 'get_extension')):
        extensions = (something.get_extension(i) for i in range(something.get_extension_count()))

    import asn1, binascii

    container_tag = asn1.Tag(0, 32, 128)

    for extension in filter(lambda e: e.get_short_name() == b'subjectAltName',
                            extensions):
        san_seq_decoder = asn1.Decoder()
        san_seq_decoder.start(extension.get_data())
        tag, value = san_seq_decoder.read()
        if tag.nr != 16: # ASN1 Sequence
            continue
        san_seq_decoder.start(value)
        while san_seq_decoder.peek():
            tag, value = san_seq_decoder.read()
            if tag != container_tag:
                continue
            # descend into container
            san_el_decoder = asn1.Decoder()
            san_el_decoder.start(value)
            tag, value = san_el_decoder.read()
            if tag.nr != 6 or value != '1.3.101.112': # check ed25519 OID
                continue
            # descend into container
            _, value = san_el_decoder.read()
            san_el_decoder.start(value)
            tag, value = san_el_decoder.read()
            if tag.nr != 2: # ASN1 Integer
                continue
            yield binascii.hexlify(value.to_bytes(32, 'big')).decode()


def get_keys_as_string(args: argparse.Namespace) -> str:
    return '\n'.join(get_keys(args)) + '\n'


COMMANDS = {
    CMD_GEN_REQ: make_req,
    CMD_GEN_CERT: make_cert,
    CMD_SIGN_REQ: sign_req,
    CMD_EXTRACT_KEYS: get_keys_as_string
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
    parser.add_argument(
        '--req',
        help='Path to certificate request in PEM format.',
        required=False)
    parser.add_argument(
        '--cert',
        help='Path to certificate in PEM format.',
        required=False)
    parser.add_argument(
        '-O',
        '--output-file',
        help=
        'Output file path. If not provided, contents will be written to stdout.',
        required=False)
    for field in OVERRIDEN_SUBJECT_FIELDS:
        parser.add_argument(f'--{field}',
                            help=f'certificate subject {OVERRIDEN_SUBJECT_FIELDS[field]}',
                            required=False)
    parser.add_argument('command', choices=COMMANDS, help="Action.")
    args = parser.parse_args()

    output_dest = args.output_file and open(args.output_file,
                                            'wt') or sys.stdout

    output_dest.write(COMMANDS[args.command](args))
