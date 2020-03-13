#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import csv
import os.path

levels = ['*', '=', '-', '^', '"']


def header_char(level):
    level = int(level) % len(levels)
    return levels[level]


def header_overline(level):
    level = int(level) % len(levels)
    return level == 0


def header(title, level):
    title = title.strip()
    decoration = header_char(level) * len(title)
    result = []
    if header_overline(level):
        result.append(decoration)
    result.append(title)
    result.append(decoration)
    result.append("")
    return result


def hint(text):
    text = text.strip()
    return ['.. Hint:: {}'.format(text), '']


def note(text):
    text = text.strip()
    return ['.. Note:: {}'.format(text), '']


def reference(link):
    if (not '#' in link) or (not '/api' in link):
        raise Exception('Badly formed input link')
    link = link.strip()
    title = link.split('#')[1].replace('-', ' ').title()
    path = ''.join(link.split("/api")[1:])
    path = '../api{}'.format(path)
    link = '`{} <{}>`__'.format(title, path)
    return link


def linkify(term, dictionary, pop=False):
    if not term:
        return term
    clean = term.strip().lower()
    before = after = ''
    if clean[0] in ['"', "'", '(']:
        before = clean[0]
        clean = clean[1:]
        term = term[1:]
    if clean[-1] in ['.', ',', '!', '?', ':', ';', '"', "'", ')']:
        after = clean[-1]
        clean = clean[:-1]
        term = term[:-1]
    result = before + term + after
    found = False
    if clean in dictionary:
        found = True
        result = '{}`{} <{}>`__{}'.format(before, term, dictionary[clean], after)
        if pop:
            dictionary.pop(clean, None)
    if not found and clean.endswith('s'):
        clean_singular = clean[:-1]
        if clean_singular in dictionary:
            result = '{}`{} <{}>`__{}'.format(before, term, dictionary[clean_singular], after)
            if pop:
                dictionary.pop(clean_singular, None)
    return result


def listing(compile_time_path, caption='', lines_range=None, lang='python'):
    """
    Generates listing lines to include
    :param compile_time_path: list of os.path primitives
    :param lines_range: tuple of two ints
    :return: rst lines
    """
    path = os.path.join(*compile_time_path)
    if not os.path.isfile(path):
        print('File not found: {} (compile time path)'.format(path))
        return []

    docs_time_path = [os.path.pardir] * 2 + list(compile_time_path)
    path = os.path.join(*docs_time_path)
    result = [
        '.. literalinclude:: {}'.format(path),
        '    :language: {}'.format(lang),
        '    :linenos:'
    ]
    if caption:
        result.append('    :caption: {}'.format(caption))
    if lines_range:
        result.append('    :lines: {}-{}'.format(lines_range[0], lines_range[1]))
    result.append('')
    return result


def excerpt_boundaries(path):
    """

    :param path: path to python example
    :return: tuple with two numbers
    """
    lines = []
    with open(path) as source:
        lines = source.readlines()
    begin = 1
    end = len(lines)
    for index, line in enumerate(lines):
        if begin == 1 and ('commons.user' in line or 'admin' in line):
            begin = index + 1
            break
    prints = spaces = False
    for index, line in reversed(list(enumerate(lines))):
        if index < end:
            if not prints and line.startswith('print'):
                prints = True
            elif prints and not line.strip():
                spaces = True
            elif prints and spaces and line.strip():
                end = index + 1
                break

    return (begin, end)


def excerpt(permission):
    """
    Renders source file listing
    :param permission: name of permission to list, used as a part of filename
    :return: rst lines
    """
    compile_time_path = [os.path.pardir] * 2 + ['example', 'python', 'permissions', '{}.py'.format(permission)]
    path = os.path.join(*compile_time_path)
    result = []
    if not os.path.isfile(path):
        print(path)
        return result
    window = excerpt_boundaries(path)
    result.extend(listing(compile_time_path, lines_range=window))
    return result


def example(text):
    """Renders example description contents"""
    result = ['**Example**', '']
    lines = text.split('\n')
    for line in lines:
        result.append('| {}'.format(line))
    result.extend(['|', ''])
    return result


def permissions_list(matrix_path):
    """Generate lines - all the permissions as a list"""
    grantable_label = '``grantable``'
    lines = [
        '.. list-table::',
        '    :header-rows: 1',
        '',
        '    * - Permission Name',
        '      - Category',
        '      - Type'
    ]
    with open(matrix_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            lines.append('    * - `{}`_ {}'.format(
                row['Permission'],
                grantable_label if row['Grantable'].strip() == 'TRUE' else ''
            ))
            lines.append('      - {}'.format(row['Category']))
            lines.append('      - {}'.format(row['Type']))
    lines.append('')
    return lines
