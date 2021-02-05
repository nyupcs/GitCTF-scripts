#!/usr/bin/env python
###############################################################################
# Git-based CTF
###############################################################################
#
# Author: SeongIl Wi <seongil.wi@kaist.ac.kr>
#         Jaeseung Choi <jschoi17@kaist.ac.kr>
#         Sang Kil Cha <sangkilc@kaist.ac.kr>
#
# Copyright (c) 2018 SoftSec Lab. KAIST
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import print_function
import subprocess
import shlex

def run_command(command, path):
    print('run_command({}, {})'.format(command, path))
    process = subprocess.Popen(shlex.split(command), cwd=path,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True)
    whole_output = ''

    for line in iter(process.stdout.readline, ''):
        if line:
            print(line.strip())
            whole_output = whole_output + line.strip()+ '\n'
        
    error = process.communicate()[1]
    print('run_command completed with code {}.'.format(process.poll()))
    return whole_output, error, process.returncode
