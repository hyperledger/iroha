#!/usr/bin/env python3

#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

'''
This is a sphinx extension that provides directives generating boilerplate
descriptions of Iroha permissions from a CSV file:
  - iroha_gen_detailed_permissions
  - iroha_gen_permissions_index
'''

import iroha_rst.permissions_compiler

from docutils import nodes
from docutils.parsers.rst import Directive
from docutils.statemachine import ViewList
from sphinx.util.nodes import nested_parse_with_titles

PERMS_COMPILER = None


def parse_raw_rst(state, lines, debug_tag):
    rst = ViewList()

    for lineno, line in enumerate(lines, 1):
        rst.append(line, debug_tag, lineno)

    node = nodes.section()
    node.document = state.document

    nested_parse_with_titles(state, rst, node)
    return node.children


class GenDetailedPermissionsDirective(Directive):
    '''
    Sphinx directive generating detailed permissions description from CSV.
    Arguments:
        1. Path to permissions CSV.
    '''

    required_arguments = 1
    optional_arguments = 0

    def run(self):
        return parse_raw_rst(
            self.state,
            PERMS_COMPILER.make_detailed(self.arguments[0]),
            'generated_detailed_permissions',
        )


class GenPermissionsIndexDirective(Directive):
    '''
    Sphinx directive generating brief permissions index from CSV.
    Arguments:
        1. Path to permissions CSV.
    '''

    required_arguments = 1
    optional_arguments = 0

    def run(self):
        return parse_raw_rst(
            self.state,
            PERMS_COMPILER.make_index(self.arguments[0]),
            'generated_permissions_index',
        )


def setup(app):
    app.add_config_value('iroha_permissions_glossary_path', None, 'html')
    global PERMS_COMPILER
    app.config.init_values()
    PERMS_COMPILER = iroha_rst.permissions_compiler.Compiler(
        app.config.iroha_permissions_glossary_path
    )
    app.add_directive('iroha_gen_detailed_permissions', GenDetailedPermissionsDirective)
    app.add_directive('iroha_gen_permissions_index', GenPermissionsIndexDirective)

    return {
        'version': '0.1',
        'parallel_read_safe': True,
        'parallel_write_safe': True,
    }
