#!/usr/bin/env python3

#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import csv
import os

import iroha_rst.common as rst

from iroha_rst.glossary import titles_to_links

class Compiler(object):
    '''Compile RST docs for permissions out of CSV. Thread safe.'''
    def __init__(self, glossary_file_path):
        self.glossary_links = titles_to_links(glossary_file_path)

    def make_detailed(self, matrix_path:str):
        perm_type = category = perm = ""

        result = []

        with open(matrix_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                grantable = False

                if row['Type'] != perm_type:
                    perm_type = row['Type']
                    result.extend(
                        rst.header("{}-related permissions".format(row['Type']), 1))

                if row['Category'] != category:
                    category = row['Category']
                    result.extend(rst.header(category, 2))

                if row['Permission'] != perm:
                    perm = row['Permission']
                    result.extend(rst.header(perm, 3))

                if row['Grantable'].strip() == 'TRUE':
                    grantable = True
                    hint = rst.hint('This is a grantable permission.')
                    result.extend(hint)

                descr_lines = row['Description'].split('\n')
                descr_lines = list(map(lambda x: x.strip(), descr_lines))
                descr_lines.append('')

                if row['Additional Information'].strip():
                    ainfo = row['Additional Information'].split('\n')
                    ainfo = list(map(lambda x: x.strip(), ainfo))
                    ainfo.append('')
                    descr_lines.extend(ainfo)

                links_dict = dict(self.glossary_links)
                descr_lines_linkified = []
                for line in descr_lines:
                    tokens = line.split(' ')
                    tokens_linkified = []
                    skip = False
                    for token in tokens:
                        if skip:
                            tokens_linkified.append(token)
                        if '`' in token:
                            if not skip:
                                tokens_linkified.append(token)
                            if token.count('`') % 2 == 1:
                                skip = not skip
                            continue
                        tokens_linkified.append(rst.linkify(token, links_dict, pop=True))
                    descr_lines_linkified.append(' '.join(tokens_linkified))

                result.extend(descr_lines_linkified)

                if row['Note'].strip():
                    result.extend(rst.note(row['Note']))

                if row['Related Command'].strip():
                    rc = row['Related Command'].split('\n')
                    rc = map(lambda x: x.strip(), rc)
                    rc = filter(lambda x: len(x) > 0, rc)
                    rc = list(rc)
                    links = []
                    related = 'Related API method' + ('s' if len(rc) > 1 else '')
                    for link in rc:
                        try:
                            links.append(rst.reference(link))
                        except Exception:
                            if (row['Related Command'].strip().lower().startswith('tbd')):
                                links.append('To be done')
                            else:
                                print(row['Related Command'])
                                raise
                    result.append('| {}: {}'.format(related, ', '.join(links)))
                    result.append('')

                if row['Example'].strip():
                    result.extend(rst.example(row['Example']))

                result.extend(rst.excerpt(perm))
            result.extend(rst.header('Supplementary Sources', 1))
            commons_path = [os.path.pardir] * 2 + ['example', 'python', 'permissions', 'commons.py']
            result.extend(rst.listing(commons_path, 'commons.py'))

        return result

    def make_index(self, matrix_path:str):
        return rst.permissions_list(matrix_path)
