#!/usr/bin/env python

"""
CI script for locating the improperly configured images
in Docker's Compose files.

Scans a list of file masks/names and checks for allowed branches.
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
            - masks: A list of file masks and names provided as positional arguments.
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
        'masks',
        nargs='*',
        help='list of file masks and exact names to be checked',
        default=[]
    )
    return parser.parse_args()

def get_paths(file_masks: List[str], root: Path):
    """
    Generate a list of pathlib.Path instances for given file masks
    and filenames within a root directory.

    This function searches for files in a specified root directory
    matching the patterns and filenames provided in `file_masks`.
    It returns a list of pathlib.Path instances for files that exist.
    Patterns can include wildcards (e.g., "*.yml").
    Only files that actually exist in the filesystem are included in the result.

    Args:
        file_masks (list of str): A list of strings representing file masks
                                  and filenames.
                                  File masks can include wildcard characters
                                  (e.g., "topic.*.yml").
        root (pathlib.Path):
                                  A pathlib.Path instance representing
                                  the root directory in which to search for files.

    Returns:
        list: A list containing pathlib.Path instances for each existing 
              file matching the file masks and filenames
              in the specified root directory.

    Raises:
        TypeError: If `root` is not an instance of pathlib.Path.

    Note:
        The function does not return paths for files that do not exist.
    """
    if not isinstance(root, Path):
        raise TypeError("The root argument must be a pathlib.Path instance")
    paths = []
    for mask in file_masks:
        if '*' in mask:
            matching_files = root.glob(mask)
            paths.extend([file for file in matching_files if file.exists()])
        else:
            path = root / mask
            if path.exists():
                paths.append(path)
            else:
                warning(f'File not found: {path.name}')
    return paths

def validate_docker_config(compose_file: Path, allow: List[str]):
    """
    Validates a single Path for a Compose config.

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
    for current_file in get_paths(args.masks, git_root()):
        if validate_docker_config(current_file, args.allow):
            warning(f'Wrong image in "{current_file.name}"')
            sys.exit(1)
    info('No incorrect Compose configurations found')

if __name__ == '__main__':
    main()
