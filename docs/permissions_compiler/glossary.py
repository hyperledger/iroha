#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

def read_titles(level_char='='):
    headings = []
    with open('concepts_architecture/glossary.rst') as gfile:
        lines = gfile.readlines()
        prevline = ''
        prevlen = 0
        for line in lines:
            line = line.strip()
            if len(line) == prevlen and line == (level_char * prevlen) and line:
                headings.append(prevline)
            prevlen = len(line)
            prevline = line
    return headings


def titles_to_links(titles):
    d = {}
    for title in titles:
        title = title.strip().lower()
        anchor = '../../concepts_architecture/glossary.html#' + title.replace(' ', '-')
        d[title] = anchor
    return d
