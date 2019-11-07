#!/usr/bin/env python3

import argparse
import os
import sys

from OpenSSL import crypto

CMD_GEN_SAN = 'gen_san'
CMD_GEN_REQ = 'gen_req'

SUBJECT_FIELDS = {
    'country': 'JP',
    'state': 'Japan',
    'locality': 'Aizu',
    'organization': 'One World',
    'organization-unit': 'example',
    'common-name': 'some iroha peer',
}


def get_iroha_pubkey(args: argparse.Namespace) -> str:
    if args.iroha_pubkey is not None:
        return args.pubkey
    elif args.iroha_pubkey_path is not None:
        assert (os.path.isfile(args.iroha_pubkey_path))
        with open(args.iroha_pubkey_path, 'rt') as inp:
            return inp.read().strip()
    raise (Exception('No iroha public key specified!'))


def get_tls_key(args: argparse.Namespace) -> crypto.PKey:
    if args.tls_key_path is not None:
        with open(args.tls_key_path, 'rt') as inp:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, inp.read())
    raise (Exception(
        'No TLS key specified! Please specify private TLS key path.'))


def make_san(args: argparse.Namespace) -> str:
    def split_key(key):
        split_key = list()
        tail = key
        while tail:
            split_key.append(tail[:63])
            tail = tail[63:]
        return split_key

    dns_key = 'iroha-node-public-key.' + '.'.join(
        split_key(get_iroha_pubkey(args)))
    return f'DNS:iroha, DNS:{dns_key}'


def make_req(args: argparse.Namespace) -> str:
    req = crypto.X509Req()
    req.get_subject().C = SUBJECT_FIELDS['country']
    req.get_subject().ST = SUBJECT_FIELDS['state']
    req.get_subject().L = SUBJECT_FIELDS['locality']
    req.get_subject().O = SUBJECT_FIELDS['organization']
    req.get_subject().OU = SUBJECT_FIELDS['organization-unit']
    req.get_subject().CN = SUBJECT_FIELDS['common-name']
    req.add_extensions([
        crypto.X509Extension(b'subjectAltName',
                             critical=True,
                             value=make_san(args).encode())
    ])
    tls_key = get_tls_key(args)
    req.set_pubkey(tls_key)
    req.sign(tls_key, 'sha1')
    return crypto.dump_certificate_request(crypto.FILETYPE_PEM, req).decode()


COMMANDS = {CMD_GEN_SAN: make_san, CMD_GEN_REQ: make_req}

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
        '-O',
        '--output-file',
        help=
        'Output file path. If not provided, contents will be written to stdout.',
        required=False)
    for field in SUBJECT_FIELDS:
        parser.add_argument(f'--{field}',
                            help=f'certificate subject {field}',
                            required=False)
    parser.add_argument('command', choices=COMMANDS)
    args = parser.parse_args()

    SUBJECT_FIELDS['common-name'] = 'iroha peer {}'.format(
        get_iroha_pubkey(args)[:5])

    output_dest = args.output_file and open(args.output_file,
                                            'wt') or sys.stdout

    SUBJECT_FIELDS.update({
        field: arg
        for field, arg in ((field, getattr(args, field.replace('-', '_')))
                           for field in SUBJECT_FIELDS) if arg is not None
    })

    if args.command in COMMANDS:
        output_dest.write(COMMANDS[args.command](args))
    else:
        print('No command specified!', file=sys.stderr)
        print('Available commands are: ' + ','.join(COMMANDS), file=sys.stderr)
        parser.print_help(file=sys.stderr)
