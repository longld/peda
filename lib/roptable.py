#!/usr/bin/env python2
## -*- coding: utf-8 -*-
##
##  PEDA - Python Exploit Development Assistance for GDB
##
##  Copyright (C) 2012 - Jonathan Salwan - http://twitter.com/JonathanSalwan
##  License: see LICENSE file for details
##
##

import os
import sys
import inspect
import traceback

from nasm import *
from utils import *



class Roptable():
    def __init__(self, arch):
        self._arch = arch
        self._gadgets_l = []
        self._regex = {
                        '_ALLREG64_' : ['rax', 'rbx', 'rcx', 'rdx', 'rdi', \
                                        'rsi', 'rsp', 'rbp', 'r8',  'r9',  \
                                        'r10', 'r11', 'r12', 'r13', 'r14', \
                                        'r15'],

                        '_ALLREG32_' : ['eax', 'ebx', 'ecx', 'edx', 'edi', \
                                        'esi', 'esp', 'ebp']
                      }

        self._parseFile()
        self._assemble()

    def __str__(self):
        return self._arch

    def _readFile(self):
        try:
            path = os.path.dirname(os.path.realpath(__file__))
            fd = open(path + '/roptable.rop', 'r')
            raw = fd.read()
            fd.close()
        except:
            traceback.print_exc()
            msg('Error: cannot open roptable.rop')
            return None
        return raw

    def _clearList(self, str):
        self._gadgets_l = filter(lambda x: x[0].find(str) == -1, self._gadgets_l)
        return

    def _replaceRegex(self, regex):
        reg_l = []
        tmp = []
        for gad in self._gadgets_l:
            if regex in gad[0]:
                tmp.append(gad[0])
                for r in self._regex[regex]:
                    reg_l.append([gad[0].replace(regex, r, 1), ''])
        for item in tmp:
            self._clearList(item)
        self._gadgets_l += reg_l
        return

    def _parseFile(self):
        raw = self._readFile()
        if raw == None:
            return None
        try:
            struct = raw.split('ARCH::%s::' %(self._arch))[1]
        except:
            msg('Error: struct name not found')
            return None
        try:
            struct = struct.split('{')[1].split('}')[0].replace('\t', '').split('\n')
        except:
            msg('Error: Core struct in roptable')
            return None

        for gad in struct:
            if len(gad):
                try:
                    self._gadgets_l.append([gad.split('\'')[1], ''])
                except:
                    msg('Error')
                    return None

        while len(filter(lambda x: x[0].find('_ALLREG64_') != -1, self._gadgets_l)) != 0:
            self._replaceRegex('_ALLREG64_')

        while len(filter(lambda x: x[0].find('_ALLREG32_') != -1, self._gadgets_l)) != 0:
            self._replaceRegex('_ALLREG32_')

        return

    def _assemble(self):
        msg("Compilation in progress...", 'yellow')
        if self._arch == 'x86-64':
            bits = 64
        elif self._arch == 'x86-32':
            bits = 32
        for ins in self._gadgets_l:
            ins[1] = Nasm.assemble(ins[0], bits)
        return

    def getGadgets(self):
        return self._gadgets_l

