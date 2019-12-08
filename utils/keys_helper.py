#!/usr/bin/env python3

import argparse

from iroha import IrohaCrypto


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--priv-in-path',
        help=
        'Path to input file with private key of iroha peer as a hex string.',
        required=False)
    parser.add_argument(
        '--priv-in',
        help='Input private key of iroha peer as a hex string.',
        required=False)
    parser.add_argument(
        '--priv-out-path',
        help='Write a newly generated private key of iroha peer '
        'to this file as a hex string.',
        required=False)
    parser.add_argument(
        '--priv-out',
        action='store_true',
        help='Write a newly generated private key of iroha peer '
        'as a hex string to stdout',
        required=False)
    parser.add_argument(
        '--pub-out-path',
        help='Write the public key of iroha peer to this file as a hex string.',
        required=False)
    parser.add_argument(
        '--pub-out',
        action='store_true',
        help='Write the public key of iroha peer as a hex string to stdout.',
        required=False)

    args = parser.parse_args()

    if args.priv_in_path:
        with open(args.priv_in_path, 'rb') as inp:
            priv_key = inp.read().strip()
    elif args.priv_in:
        priv_key = args.priv_in.strip()
    else:
        priv_key = IrohaCrypto.private_key()

    try:
        pub_key = IrohaCrypto.derive_public_key(priv_key)
    except:
        print('Bad private key!')
        raise

    if args.priv_out_path:
        with open(args.priv_out_path, 'wb') as out:
            out.write(priv_key)

    if args.priv_out:
        print('private key: {}'.format(priv_key.decode()))

    if args.pub_out_path:
        with open(args.pub_out_path, 'wb') as out:
            out.write(pub_key)

    if args.pub_out:
        print('public key:  {}'.format(pub_key.decode()))
