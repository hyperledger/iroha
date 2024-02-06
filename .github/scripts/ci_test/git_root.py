"""
This module contains a modified copy of git_root by Jan Tilly.
It allows to find a repo root on GitHub for the CI purposes.

https://github.com/jtilly/git_root/blob/master/git_root/git_root.py
"""

from subprocess import Popen, PIPE, DEVNULL
from os.path import abspath
from pathlib import Path

def git_root():
    root = '.'
    with Popen(
        ['git', 'rev-parse', '--show-toplevel'],
        stdout=PIPE, stderr=DEVNULL
    ) as git_proc:
        root = git_proc.communicate()[0].rstrip().decode('utf-8')
    return Path(abspath(root))
