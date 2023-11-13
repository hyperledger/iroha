#!/usr/bin/env python

"""
CI script for locating the improperly configured images
in Docker's Compose files.

Scans a list of filenames and checks for allowed branches.
"""

from typing import List
import sys
from logging import getLogger, warning, error, info, INFO
from argparse import ArgumentParser, Namespace
from pathlib import Path
from yaml import safe_load
from yaml.error import YAMLError
from git_root import git_root

def parse_arguments() -> Namespace:
    """
    Returns:
        Namespace: An object containing two attributes:
            - filenames: A list of file names provided as positional arguments.
            - allow: A list of Docker images provided
                     to the 'allow' option, or [] if not provided.
    """
    parser = ArgumentParser(description='Process some file names.')
    parser.add_argument(
        '--allow',
        nargs='+',
        help='one or more allowed image names',
        default=[]
    )
    parser.add_argument(
        'filenames',
        nargs='*',
        help='list of file names',
        default=[]
    )
    return parser.parse_args()

def check_docker_config(compose_file: Path, allow: List[str]):
    """
    Checks a single Path for a Compose config.

    Returns:
        (int) 1 if the image is using a config that isn't allowed,
              0 otherwise
    """
    status = 0
    services = {}
    try:
        with open(compose_file, 'r', encoding='utf8') as compose_file_contents:
            config_inst = safe_load(compose_file_contents.read())
            if isinstance(config_inst, dict):
                services = config_inst.get('services', {})
            else:
                error(f'Improper configuration at "{compose_file}"')
                status = 1
    except YAMLError:
        error(f'Improper formatting at "{compose_file}"')
        status = 1
    for _, service in services.items():
        if service.get('image', '') not in allow:
            status = 1
            break
    return status

def main():
    """
    Validate the supplied Docker configurations
    and exit with an error if one of them is using
    an incorrect image.
    """
    getLogger().setLevel(INFO)
    args = parse_arguments()
    for filename in args.filenames:
        current_file = git_root() / filename
        if check_docker_config(current_file, args.allow):
            warning(f'Wrong image in "{filename}"')
            sys.exit(1)
    info('No incorrect Compose configurations found')

if __name__ == '__main__':
    main()
