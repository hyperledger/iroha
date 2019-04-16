#!/usr/bin/env python3
#
# Copyright Soramitsu Co., Ltd. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#

import platform
import os

prompt = '''
This is an utility for configuring environment before Locust is run.

If the default (value) is ok just press Return
'''
print(prompt)

host = 'docker.for.mac.localhost' if 'darwin' == platform.system(
).lower() else '127.0.0.1'
port = '50051'


def ask(prompt, default_value):
    result = input('{} ({}): '.format(prompt, default_value))
    if not result:
        result = default_value
    print('\tset value={}'.format(result))
    return result


host = ask('Enter Iroha address', host)
port = ask('Enter Iroha torii port', port)


directory = os.path.dirname(os.path.abspath(__file__))
os.chdir(directory)
print('Working directory set to {}'.format(directory))

locust_scripts = []
for _, _, files in os.walk('.'):
    for script in files:
        if script.endswith('.py'):
            if 'update-env.py' != script:
                locust_scripts.append(script)
    break

print('\nAvailable scripts:')
for x in enumerate(locust_scripts):
    print('{} - {}'.format(x[0], x[1]))

script = int(ask('Enter a number of required script', '0'))
script %= len(locust_scripts)
locust_script = locust_scripts[script]

config = [
    'TARGET_URL={}:{}'.format(host, port),
    'LOCUSTFILE_PATH=/tests/{}'.format(locust_script),
    ''
]

print('\nResulting config:')
for line in config:
    print(line)

with open('config.env', 'w') as file:
    file.write('\n'.join(config))
    file.flush()
    print('saved.')
