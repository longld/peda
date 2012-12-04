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

        self._parsefile()
        self._assemble()

    def __str__(self):
        return self._arch

    def _readfile(self):
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

    def _parsefile(self):
        raw = self._readfile()
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

        return self._gadgets_l

    def _assemble(self):
        if self._arch == 'x86-64':
            bits = 64
        elif self._arch == 'x86-32':
            bits = 32
        for ins in self._gadgets_l:
            ins[1] = Nasm.assemble(ins[0], bits)
        return

    def getGadgets(self):
        return self._gadgets_l

