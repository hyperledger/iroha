#!/usr/bin/env python

import hashlib
import argparse
import os

WINDOWS_LINE_ENDING = b'\r\n'
UNIX_LINE_ENDING = b'\n'


def md5_update_from_dir(directory, hash):
    assert os.path.isdir(directory)
    for root, dirnames, filenames in os.walk(directory):
        for file in sorted(filenames, key=lambda p: str(p).lower()):
            # If you need include file name to hash uncomment this
            #hash.update(file.encode())
            with open(os.path.join(root, file), "rb") as f:
                hash.update(f.read().replace(WINDOWS_LINE_ENDING, UNIX_LINE_ENDING))
        for path in sorted(dirnames, key=lambda p: str(p).lower()):
            hash = md5_update_from_dir(os.path.join(root, path), hash)
    return hash


def md5_dir(directory):
    return md5_update_from_dir(directory, hashlib.md5()).hexdigest()


parser = argparse.ArgumentParser(description='Calculate MD5 hash for given folder')
parser.add_argument('folder')
args = parser.parse_args()

print(md5_dir(args.folder)[0:4])
