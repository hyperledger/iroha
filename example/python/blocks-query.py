#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import sys

if sys.version_info[0] < 3:
    raise Exception('Python 3 or a more recent version is required.')


from irohalib import IrohaCrypto
from irohalib import Iroha, IrohaGrpc


admin_private_key = open('../admin@test.priv').read()
iroha = Iroha('admin@test')
net = IrohaGrpc()


def trace(func):
    """
    A decorator for tracing methods' begin/end execution points
    """
    def tracer(*args, **kwargs):
        name = func.__name__
        print('\tEntering "{}"'.format(name))
        result = func(*args, **kwargs)
        print('\tLeaving "{}"'.format(name))
        return result
    return tracer


@trace
def get_blocks():
    """
    Subscribe to blocks stream from the network
    :return:
    """
    query = iroha.blocks_query()
    IrohaCrypto.sign_query(query, admin_private_key)
    for block in net.send_blocks_stream_query(query):
        print('The next block arrived:', block)


get_blocks()
