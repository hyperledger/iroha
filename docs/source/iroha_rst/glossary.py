#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

def titles_to_links(glossary_file_path, level_char='='):
    links = dict()
    anchor_base = '{}#{{}}'.format(glossary_file_path)
    with open(glossary_file_path) as gfile:
        prevline = ''
        prevlen = 0
        for line in gfile.readlines():
            line = line.strip().lower()
            if line and len(line) == prevlen and all(
                    map(lambda x: x == level_char, line)):
                links[prevline] = anchor_base.format(
                    glossary_file_path, prevline.replace(' ', '-'))
                prevlen = 0
                prevline = ''
            else:
                prevlen = len(line)
                prevline = line
    return links
