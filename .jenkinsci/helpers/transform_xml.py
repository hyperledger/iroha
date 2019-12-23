#!/usr/env/python
#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

#
# Transforms an XML file using XSLT
#

import lxml.etree as ET
import argparse

parser = argparse.ArgumentParser(description='Transform an XML file using XSLT')
for arg in ['xslt_transform_file', 'xml_report_file']:
	parser.add_argument(arg)
args = parser.parse_args()

tree = ET.parse(args.xml_report_file)
xslt = ET.parse(args.xslt_transform_file)
transform = ET.XSLT(xslt)
new_tree = transform(tree)
new_tree.write(args.xml_report_file)
